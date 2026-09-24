package main

import (
	"fmt"
	"strings"
	"testing"
)

// Benchmarks pin the hot path — SimHash + judge — to a wall-time baseline so a future
// optimization attempt can prove it didn't regress. Run with:
//   go test -bench=. -benchmem -run=^$ ./...
// Baselines (Apple M-series, in-repo, ~2026-09):
//   BenchmarkSimHash_HTMLPage        ~120 µs/op    ~0 B/op after log-damp accumulator
//   BenchmarkSimHash_JSONShortBody    ~10 µs/op
//   BenchmarkJudge_TypicalProfile     ~0.05 µs/op
//   BenchmarkCollapse_100Findings    ~200 µs/op

// realisticHTML is a body the size a scan actually sees — ~4 KB of markup with a mix of
// tags, English + digits, and repeated tokens (Zipf-shaped, like a real page). Sized to
// stay under the calibration probe cap so BenchmarkSimHash reflects the hot path.
var realisticHTML = func() string {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><title>Admin Console</title><meta charset="utf-8"/>`)
	sb.WriteString(`<link rel="stylesheet" href="/static/app.css"/></head><body>`)
	sb.WriteString(`<nav>home users roles billing analytics reports export logs settings</nav>`)
	sb.WriteString(`<main><h1>Welcome back</h1>`)
	// Repeat a paragraph a few times to get into the 4 KB range without pathological entropy.
	para := `<p>Session tokens rotate every hour. Contact support if you need a longer window. ` +
		`Export queues run daily at 02:00 UTC and 14:00 UTC.</p>`
	for i := 0; i < 15; i++ {
		fmt.Fprintf(&sb, "%s", para)
	}
	sb.WriteString(`<table><tr><th>ID</th><th>Name</th><th>Email</th><th>Status</th></tr>`)
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&sb, "<tr><td>%d</td><td>user%d</td><td>u%d@acme.tld</td><td>active</td></tr>", i, i, i)
	}
	sb.WriteString(`</table></main></body></html>`)
	return sb.String()
}()

// jsonShortBody is the SPA/API not-found shape: small, JSON-envelope, high semantic density
// per token. Judge's hot path fires for every candidate, so this benchmarks the sub-µs case.
var jsonShortBody = `{"error":"not found","code":404,"path":"/admin/users/999","request_id":"abc123"}`

// BenchmarkSimHash_HTMLPage — the calibration probe hot path on realistic HTML.
func BenchmarkSimHash_HTMLPage(b *testing.B) {
	body := realisticHTML
	b.ResetTimer()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		_ = SimHash(body)
	}
}

// BenchmarkSimHash_JSONShortBody — the API-shape hot path (soft-404 JSON envelope).
func BenchmarkSimHash_JSONShortBody(b *testing.B) {
	body := jsonShortBody
	b.ResetTimer()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		_ = SimHash(body)
	}
}

// BenchmarkJudge_TypicalProfile — verify() calls judge on every candidate. A regression
// here scales linearly with candidate count (20k for a wide scan) so sub-µs matters.
func BenchmarkJudge_TypicalProfile(b *testing.B) {
	nf1 := SimHash("<title>404</title>not found aaaa " + strings.Repeat("filler ", 10))
	nf2 := SimHash("<title>404</title>not found bbbb " + strings.Repeat("filler ", 10))
	p := Profile{
		Statuses: map[int]bool{200: true, 404: true},
		Titles:   map[string]bool{"": true},
		TitleStable: true,
		Sims: []uint64{nf1, nf2}, Threshold: 12, Margin: 2,
	}
	r := Resp{Status: 200, Sim: SimHash("<title>Admin</title>dashboard settings")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.judge(r)
	}
}

// BenchmarkCollapse_100Findings — the post-scan collapse pass. Regressing here would
// bite a wide-scan (--collapse enabled, hundreds of walled 403s) at output time.
func BenchmarkCollapse_100Findings(b *testing.B) {
	// Build a mixed set: 80 near-identical 403s (sim=0xAAAA-ish, ≤2 bits apart), plus 20
	// distinct 200s. Matches a WAF-fronted scan's collapse footprint.
	fs := make([]Finding, 0, 100)
	for i := 0; i < 80; i++ {
		fs = append(fs, Finding{
			URL: fmt.Sprintf("http://h/wall/%d", i),
			Status: 403, Sim: 0xAAAA,
		})
	}
	for i := 0; i < 20; i++ {
		fs = append(fs, Finding{
			URL: fmt.Sprintf("http://h/page/%d", i),
			Status: 200, Sim: uint64(0x1000 + i*7919), // spread apart
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collapse(fs, 5)
	}
}
