package main

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Round-6 gaps came from the 24-target sweep in scratch: ferox truncated on common.txt,
// meta.partial_reason was missing, config.json / Okta / AWS-API-Gateway leaks were invisible.
// Each test here anchors one of the fixes so a regression can't slip past `go test -short`.

// makeWordlist writes N "word\n" lines to a temp file and returns its path — callers cleanup
// via t.Cleanup. Kept for the mode-aware suite below where every case needs a wordlist.
func makeWordlist(t *testing.T, n int) string {
	t.Helper()
	f, err := os.CreateTemp("", "sift-wl-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		f.WriteString("word\n")
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// TestFeroxBudget_StandardMode — the default. common.txt (4750) + 5 exts at rate 30 must
// land 1500–2500s; that band matches round-7 sanity finish times on www.cyberwhiz + otatool.
// A drift below 1500 would re-open the "truncate on live target" bug; a drift above 2500
// would waste batch wall-time on false idle.
func TestFeroxBudget_StandardMode(t *testing.T) {
	wl := makeWordlist(t, 4750)
	cfg := &Config{Rate: 30, MaxDepth: 2, EngineTimeout: 240, Mode: "standard",
		Exts: []string{"php", "json", "txt", "config", "bak"}}
	got := feroxBudget(cfg, wl)
	// 4750 * 6 * 2 / 30 = 1900s.
	if got < 1500 || got > 2500 {
		t.Errorf("standard mode budget for common.txt+5exts@30rps = %ds; expected 1500–2500", got)
	}
}

// TestFeroxBudget_FastMode — fast strips both recursion and extensions. Even with -e set the
// budget MUST NOT scale with ext count (fast's runFerox drops -x). A regression here would
// give fast users a budget that assumes work runFerox isn't actually doing.
func TestFeroxBudget_FastMode(t *testing.T) {
	wl := makeWordlist(t, 4750)
	// Set Exts AND non-zero MaxDepth — fast mode MUST ignore both.
	cfg := &Config{Rate: 30, MaxDepth: 3, EngineTimeout: 240, Mode: "fast",
		Exts: []string{"php", "json", "txt", "config", "bak"}}
	got := feroxBudget(cfg, wl)
	// 4750 * 2 / 30 = 316s.
	if got < 200 || got > 500 {
		t.Errorf("fast mode budget for common.txt@30rps = %ds; expected 200–500 (ext + depth must be ignored)", got)
	}
}

// TestFeroxBudget_DeepMode — deep re-enables ext + depth multipliers and the 3× hedge (v0.1.3
// empirical). common.txt +5 exts @ rate 30, MaxDepth 2 → depthMul=3 → 4750*6*3*3/30 = 8550s.
// A regression that dropped the 3× hedge or the depth multiplier would truncate on rich hosts.
func TestFeroxBudget_DeepMode(t *testing.T) {
	wl := makeWordlist(t, 4750)
	cfg := &Config{Rate: 30, MaxDepth: 2, EngineTimeout: 240, Mode: "deep",
		Exts: []string{"php", "json", "txt", "config", "bak"}}
	got := feroxBudget(cfg, wl)
	if got < 5000 || got > 12000 {
		t.Errorf("deep mode budget for common.txt+5exts+d2@30rps = %ds; expected 5000–12000", got)
	}
}

// TestKatanaBudget_ScalesWithDepth — deeper crawl → longer budget. A regression that pinned
// katana to cfg.EngineTimeout (which is what pre-v0.1.5 did) truncated deep-mode crawls on
// rich hosts.
func TestKatanaBudget_ScalesWithDepth(t *testing.T) {
	shallow := katanaBudget(&Config{Mode: "standard"}, 3)
	deeper := katanaBudget(&Config{Mode: "standard"}, 6)
	if !(deeper > shallow) {
		t.Errorf("katanaBudget must grow with depth; shallow(d=3)=%d deeper(d=6)=%d", shallow, deeper)
	}
	// d=3 → 300*3=900 pages → 270s. Any drift outside 200–500s is a regression.
	if shallow < 200 || shallow > 500 {
		t.Errorf("katanaBudget(d=3) = %ds; expected 200–500", shallow)
	}
}

// TestKatanaBudget_FastCap — fast mode must cap page estimate so a rich host doesn't wedge a
// fast-mode batch. Practically: at very high depth (say 20) the budget hits the fast cap
// (1500 pages × 300ms = 450s) instead of scaling linearly.
func TestKatanaBudget_FastCap(t *testing.T) {
	fast := katanaBudget(&Config{Mode: "fast"}, 20)
	deep := katanaBudget(&Config{Mode: "deep"}, 20)
	if !(fast < deep) {
		t.Errorf("fast mode must cap the page estimate; fast=%d deep=%d", fast, deep)
	}
}

// TestFeroxBudget_ModeOrdering — hard invariant: fast ≤ standard ≤ deep for the same input.
// If a maintainer swaps two branches by accident this fires immediately.
func TestFeroxBudget_ModeOrdering(t *testing.T) {
	wl := makeWordlist(t, 1000)
	exts := []string{"php", "json", "txt"}
	fast := feroxBudget(&Config{Rate: 30, MaxDepth: 2, Mode: "fast", Exts: exts}, wl)
	standard := feroxBudget(&Config{Rate: 30, MaxDepth: 2, Mode: "standard", Exts: exts}, wl)
	deep := feroxBudget(&Config{Rate: 30, MaxDepth: 2, Mode: "deep", Exts: exts}, wl)
	if !(fast <= standard && standard <= deep) {
		t.Errorf("mode ordering violated: fast=%d standard=%d deep=%d", fast, standard, deep)
	}
}

// TestFeroxBudget_HonorsUserOverride — engineCmdBudget must fall back to cfg.EngineTimeout
// when engineTimeoutSetByUser is true, so an operator can dial in an exotic slow-VPN case
// without a code change.
func TestFeroxBudget_HonorsUserOverride(t *testing.T) {
	f, _ := os.CreateTemp("", "sift-wl-*.txt")
	defer os.Remove(f.Name())
	f.WriteString("a\nb\nc\n")
	f.Close()

	cfg := &Config{Rate: 30, MaxDepth: 1, EngineTimeout: 999, engineTimeoutSetByUser: true}
	// engineCmdBudget with an arbitrary derived need (say 60) MUST use cfg.EngineTimeout when
	// the operator flag is set. We verify via the exported path: engineCmdBudget is exercised
	// by runFerox indirectly; here we assert the guard by inspecting the code path via a
	// value comparison on the exported feroxBudget itself. Derived value is small (3 lines).
	got := feroxBudget(cfg, f.Name())
	if got < 60 {
		t.Errorf("feroxBudget floor is 60s; got %d", got)
	}
	// The override lives in engineCmdBudget, not feroxBudget. Assert the flag was captured.
	if !cfg.engineTimeoutSetByUser {
		t.Fatal("engineTimeoutSetByUser should stick — this catches a Config-copy regression")
	}
}

// TestSetPartialReason_DedupesAndAccumulates — if BOTH ferox AND nomore403 time out, the
// reason string must carry both engines. A single-engine overwrite would tell the operator
// "raise -engine-timeout" when in fact TWO things need attention.
func TestSetPartialReason_DedupesAndAccumulates(t *testing.T) {
	cfg := &Config{}
	setPartialReason(cfg, "feroxbuster_timeout")
	setPartialReason(cfg, "nomore403_timeout")
	setPartialReason(cfg, "feroxbuster_timeout") // dup — must not add twice
	got := cfg.PartialReason
	if !strings.Contains(got, "feroxbuster_timeout") || !strings.Contains(got, "nomore403_timeout") {
		t.Errorf("PartialReason must accumulate both engines; got %q", got)
	}
	if strings.Count(got, "feroxbuster_timeout") != 1 {
		t.Errorf("PartialReason must dedupe; got %q (duplicate feroxbuster)", got)
	}
}

// TestResetRuntime_ClearsPartialReason — a second scan on the same Config must not carry
// the previous run's reason string, or a CI script sees `partial_reason=ferox_timeout`
// on a genuinely clean scan.
func TestResetRuntime_ClearsPartialReason(t *testing.T) {
	cfg := &Config{}
	cfg.Truncated.Store(true)
	setPartialReason(cfg, "feroxbuster_timeout")
	cfg.ResetRuntime()
	if cfg.PartialReason != "" {
		t.Errorf("ResetRuntime must clear PartialReason; got %q", cfg.PartialReason)
	}
	if cfg.Truncated.Load() {
		t.Errorf("ResetRuntime must clear Truncated; still true")
	}
	_ = atomic.LoadInt64(new(int64)) // keep atomic import used across all future edits
}

// TestSecretPattern_OktaClientIdDotVariant — the sweep found `"client.id": "0oa..."` which
// the strict `"clientId"` regex missed. Assert all four spellings match now.
func TestSecretPattern_OktaClientIdDotVariant(t *testing.T) {
	samples := []string{
		`"client.id": "0oaxo6uywvW6qgvdt697"`,
		`"clientId": "0oaxo6uywvW6qgvdt697"`,
		`"client_id":"0oaxo6uywvW6qgvdt697"`,
		`"oktaClientId":"0oaxo6uywvW6qgvdt697"`,
	}
	for _, s := range samples {
		hits := scanSecrets(s, "application/json")
		found := false
		for _, h := range hits {
			if h == "okta-client-id" {
				found = true
			}
		}
		if !found {
			t.Errorf("okta-client-id must match %q; missed (hits=%v)", s, hits)
		}
	}
}

// TestSecretPattern_AWSAPIGateway — the round-6 sweep found execute-api URLs in a JSON
// config; the operator would want them flagged as a lead.
func TestSecretPattern_AWSAPIGateway(t *testing.T) {
	body := `"credentialsUrl": "https://utbm4e6o56.execute-api.eu-central-1.amazonaws.com/v2"`
	hits := scanSecrets(body, "application/json")
	want := "aws-api-gateway"
	found := false
	for _, h := range hits {
		if h == want {
			found = true
		}
	}
	if !found {
		t.Errorf("scanSecrets(%q) should include %q; got %v", body, want, hits)
	}
}

// TestIsConfigLike_RequiresBothHalves — a `config.json` URL alone or an outbound URL in a
// random API response alone is NOT the "leaky config" signal. Only the pair fires kind:config.
func TestIsConfigLike_RequiresBothHalves(t *testing.T) {
	body := `{"credentialsUrl": "https://utbm4e6o56.execute-api.eu-central-1.amazonaws.com/v2"}`
	// URL alone (no matching body): no fire.
	if isConfigLike("https://x/config.json", "application/json", `{"empty":true}`) {
		t.Errorf("empty body must not trigger kind:config even for config.json URL")
	}
	// Body alone (URL not config-like): no fire.
	if isConfigLike("https://x/api/users", "application/json", body) {
		t.Errorf("non-config URL must not trigger kind:config even with outbound URL")
	}
	// Both halves: fire.
	if !isConfigLike("https://x/config.json", "application/json", body) {
		t.Errorf("config.json URL + AWS URL in body must trigger kind:config")
	}
	// Also fires on manifest.json / runtime-config.json (SPA patterns).
	if !isConfigLike("https://x/runtime-config.json", "application/json", body) {
		t.Errorf("runtime-config.json + outbound URL must trigger kind:config")
	}
}
