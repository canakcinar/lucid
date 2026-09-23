package main

import (
	"fmt"
	"strings"
	"testing"
)

// The property that makes sift work: two soft-404 pages that differ only in a variable-length
// filler (ads, nonce, reflected path) stay CLOSE, while a real page is FAR — something an
// exact-length or size filter cannot see.
func TestSimHashSeparatesSoft404FromReal(t *testing.T) {
	// Realistic soft-404 template with a variable-length filler (ads/nonce/reflected path) —
	// the case that defeats an exact-length or size filter.
	// Same not-found template; variants differ only by the reflected path and a variable-length
	// (same-vocabulary) filler — how real dynamic soft-404s actually vary.
	tmpl := `<html><head><title>Page Not Found</title></head><body>
<nav>home products services pricing blog about contact login signup</nav>
<main><h1>Sorry</h1><p>The page %s you requested could not be found on this server.</p>
<p>Try our search or return to the homepage.</p>
<div class="suggest">%s</div></main>
<footer>copyright acme corp all rights reserved privacy terms</footer></body></html>`
	soft1 := fmt.Sprintf(tmpl, "/admin", strings.Repeat("item ", 3))
	soft2 := fmt.Sprintf(tmpl, "/backup", strings.Repeat("item ", 30))
	real := `<html><head><title>Admin Dashboard</title></head><body>
<nav>users roles billing audit settings integrations tokens</nav>
<main><h1>Welcome back</h1><table><tr>id name email status created</tr></table>
<form action="/export">generate download report csv</form></main>
<footer>session logout support</footer></body></html>`

	dSoft := Hamming(SimHash(soft1), SimHash(soft2))
	dReal := Hamming(SimHash(soft1), SimHash(real))
	t.Logf("soft↔soft=%d  soft↔real=%d", dSoft, dReal)
	if dSoft >= dReal {
		t.Fatalf("soft-404 variants (%d) should be nearer than a real page (%d)", dSoft, dReal)
	}
	if dReal-dSoft < 8 {
		t.Fatalf("separation too small: soft=%d real=%d", dSoft, dReal)
	}
}

func TestSimHashEmpty(t *testing.T) {
	if SimHash("") != 0 {
		t.Fatal("empty body should hash to 0")
	}
}

// Two Chinese bodies whose only shared token is `error` (ASCII scaffolding) MUST hash
// to materially different SimHashes. Before the Unicode tokenizer fix the CJK content
// dropped entirely and the two hashes collided, so any localized real endpoint sharing
// the same JSON envelope was misjudged as a soft-404.
func TestSimHashUnicodeTokens_ChineseDistinct(t *testing.T) {
	a := `{"error":"页面未找到:管理后台"}`
	b := `{"error":"欢迎回来,请选择要导出的报表类型"}`
	d := Hamming(SimHash(a), SimHash(b))
	if d < 10 {
		t.Fatalf("distinct Chinese bodies collapsed: hamming=%d (want >=10)", d)
	}
}

// Localized (Turkish) soft-404 template must stay CLOSE to its variants and FAR from a
// distinct localized real page — the same separation the English fixture asserts. The
// pre-fix ASCII-only tokenizer would drop all Turkish words and score both distances near 0.
func TestSimHashSeparatesSoft404FromReal_Turkish(t *testing.T) {
	tmpl := `<html><head><title>Sayfa Bulunamadı</title></head><body>
<nav>anasayfa ürünler hizmetler fiyatlandırma blog hakkımızda iletişim giriş kayıt</nav>
<main><h1>Üzgünüz</h1><p>İstediğiniz sayfa %s bu sunucuda bulunamadı.</p>
<p>Aramamızı deneyin veya anasayfaya dönün.</p>
<div class="öneri">%s</div></main>
<footer>telif hakkı acme şirketi tüm hakları saklıdır gizlilik şartlar</footer></body></html>`
	soft1 := fmt.Sprintf(tmpl, "/yönetim", strings.Repeat("öğe ", 3))
	soft2 := fmt.Sprintf(tmpl, "/yedekleme", strings.Repeat("öğe ", 30))
	real := `<html><head><title>Yönetim Paneli</title></head><body>
<nav>kullanıcılar roller faturalama denetim ayarlar entegrasyonlar belirteçler</nav>
<main><h1>Tekrar hoş geldiniz</h1><table><tr>kimlik ad eposta durum oluşturuldu</tr></table>
<form action="/dışa">rapor csv oluştur indir</form></main>
<footer>oturum çıkış destek</footer></body></html>`

	dSoft := Hamming(SimHash(soft1), SimHash(soft2))
	dReal := Hamming(SimHash(soft1), SimHash(real))
	t.Logf("tr soft↔soft=%d  tr soft↔real=%d", dSoft, dReal)
	if dSoft >= dReal {
		t.Fatalf("Turkish soft-404 variants (%d) should be nearer than a real page (%d)", dSoft, dReal)
	}
	if dReal-dSoft < 8 {
		t.Fatalf("Turkish separation too small: soft=%d real=%d", dSoft, dReal)
	}
}

// Regression: the judge must keep a distinct page and drop a same-template soft-404, even when
// both return 200 — the core separation guarantee, across HTML and JSON shapes.
func TestJudgeSeparation(t *testing.T) {
	nf1 := `{"error":"not found","code":404,"path":"/aaaa"}`
	nf2 := `{"error":"not found","code":404,"path":"/bbbbbbbb"}`
	p := Profile{Statuses: map[int]bool{200: true}, Titles: map[string]bool{"": true}, TitleStable: true,
		Sims: []uint64{SimHash(nf1), SimHash(nf2)}, Threshold: 12, Margin: 2}
	real := Resp{Status: 200, Sim: SimHash(`{"data":[{"id":1,"vin":"WN1"}],"count":42,"columns":["id","vin"]}`)}
	if v, _ := p.judge(real); v != VHit {
		t.Fatalf("distinct JSON endpoint must be a hit, got %v", v)
	}
	soft := Resp{Status: 200, Sim: SimHash(`{"error":"not found","code":404,"path":"/cccc"}`)}
	if v, _ := p.judge(soft); v != VNotFound {
		t.Fatalf("soft-404 JSON must be dropped, got %v", v)
	}
}
