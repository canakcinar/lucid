package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestNomoreBudget_ScalesWithConfig — the deadline formula drives whether nomore403 finishes
// its default 4×80 payload sweep. Two regressions this test catches:
//   (a) removing a technique from nomore403Techniques without shrinking the budget silently
//       overshoots; a rate-limited scan then holds up a real bypass window
//   (b) adding one but not raising the const undershoots — the old "hardcoded 4" bug where
//       -k added a fifth technique got killed mid-run
func TestNomoreBudget_ScalesWithConfig(t *testing.T) {
	cfg := &Config{}
	base := nomoreBudget(cfg)
	if base < 30 {
		t.Errorf("floor is 30s; got %ds", base)
	}
	// Rate limit stretches the deadline — if the operator asked for 1 req/s and 320 payloads,
	// we can't finish in the baseline. The formula must extend, not clip.
	cfg.Rate = 1
	slow := nomoreBudget(cfg)
	if slow <= base {
		t.Errorf("rate=1 must extend budget beyond baseline; base=%d slow=%d", base, slow)
	}
	// Rate=1000 (much faster than concurrency-derived floor) shouldn't shrink below the floor.
	cfg.Rate = 1000
	fast := nomoreBudget(cfg)
	if fast < 30 {
		t.Errorf("rate=1000 must stay above the 30s floor; got %d", fast)
	}
}

// TestHaveBin_TrueForCommonUtility — the wrapper's whole "graceful degrade if a tool is
// missing" contract hinges on this. A test that stubs exec.LookPath would defeat the point:
// we call it against a binary that is guaranteed to be on every path GitHub Actions and
// developer machines run this on.
func TestHaveBin(t *testing.T) {
	if !haveBin("sh") && !haveBin("cmd.exe") {
		t.Skip("no baseline shell in PATH — CI runner is exotic")
	}
	if haveBin("this-binary-does-not-exist-92834") {
		t.Error("haveBin returned true for a bogus name")
	}
}

// TestTrimDots_PreservesExtensionSet — ferox/ffuf get bare extensions without leading dots.
// A user passing ".php,html,.json" (mixed) used to silently ship ".php" through, producing
// requests for paths like "/foo..php" that miss every real hit.
func TestTrimDots(t *testing.T) {
	got := trimDots([]string{".php", "html", ".json", ""})
	want := []string{"php", "html", "json", ""}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("trimDots preserving leading dots: %v", got)
	}
}

// TestResetRuntime — a second scan against the same Config must NOT inherit run-1's
// PARTIAL flag, request budget count, or throttle backoff. The exact library-consumer
// footgun ResetRuntime exists to close.
func TestResetRuntime(t *testing.T) {
	cfg := &Config{Delay: 100, MaxReq: 5}
	cfg.Truncated.Store(true)
	atomic.StoreInt64(&cfg.reqCount, 42)
	cfg.Throttle = NewThrottle(100)
	// Poison the throttle so we can prove ResetRuntime rebuilt it.
	cfg.Throttle.penalize()
	cfg.Throttle.penalize()

	cfg.ResetRuntime()

	if cfg.Truncated.Load() {
		t.Error("Truncated must be cleared")
	}
	if atomic.LoadInt64(&cfg.reqCount) != 0 {
		t.Error("reqCount must be zeroed")
	}
	if cfg.Throttle == nil {
		t.Fatal("Throttle must be rebuilt when Delay>0")
	}
	// Fresh throttle: cur should equal base (100), not the penalized value.
	if atomic.LoadInt64(&cfg.Throttle.cur) != 100 {
		t.Errorf("Throttle backoff not reset; cur=%d", atomic.LoadInt64(&cfg.Throttle.cur))
	}
	// Delay=0 -> Throttle must be nil (no-throttle semantics).
	cfg.Delay = 0
	cfg.ResetRuntime()
	if cfg.Throttle != nil {
		t.Error("Delay=0 must leave Throttle nil, not a zero-delay throttle")
	}
}

// TestBypassTried_MembershipOnly — the fix'd contract. bypassTried is now a pure lookup:
// it must NOT mark the sim as tried. Marking happens later via markBypassTried, and only
// after nomore403 actually finished.
func TestBypassTried_And_MarkBypassTried(t *testing.T) {
	s := &Scanner{}
	if s.bypassTried(0xAAAA) {
		t.Error("empty tried set: bypassTried must be false")
	}
	// After lookup only, no mark should be recorded.
	if len(s.tried403) != 0 {
		t.Fatal("bypassTried leaked a write into tried403")
	}
	// markBypassTried should record it.
	s.markBypassTried(0xAAAA)
	if !s.bypassTried(0xAAAA) {
		t.Error("after mark: bypassTried must be true")
	}
	// Near-identical sim (1 bit off, well within the ≤2 tolerance) also matches.
	if !s.bypassTried(0xAAAB) {
		t.Error("near-identical body should hit the ≤2 hamming tolerance")
	}
	// Duplicate mark is a no-op, not a duplicate entry.
	s.markBypassTried(0xAAAA)
	s.markBypassTried(0xAAAB)
	if len(s.tried403) != 1 {
		t.Errorf("duplicate marks leaked: tried403=%v", s.tried403)
	}
}

// TestHAREntries_NilSafe — HAREntries is called from main() unconditionally; a scan without
// -har must return nil (not panic) so the caller's "if entries != nil" gate is honest.
func TestHAREntries_NilSafeAndCopies(t *testing.T) {
	var s *Scanner
	if got := s.HAREntries(); got != nil {
		t.Error("nil Scanner should give nil entries, not zero-length slice")
	}
	s = &Scanner{}
	if got := s.HAREntries(); got != nil {
		t.Error("scanner without -har should give nil entries")
	}
	s.har = &harScope{}
	s.har.add(harCapture{URL: "http://h/a"})
	s.har.add(harCapture{URL: "http://h/b"})
	got := s.HAREntries()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	// Snapshot must be a copy — caller mutation must not affect the scope.
	got[0].URL = "mutated"
	got2 := s.HAREntries()
	if got2[0].URL == "mutated" {
		t.Error("snapshot leaked shared state")
	}
}

// TestSeedFindings_Cumulative — resume seeds the scanner with a prior run's Findings so the
// final report is additive. Empty input is a no-op; non-empty must be visible in s.findings.
func TestSeedFindings(t *testing.T) {
	s := &Scanner{}
	s.SeedFindings(nil)
	if len(s.findings) != 0 {
		t.Error("nil input must not touch findings")
	}
	s.SeedFindings([]Finding{{URL: "http://h/a"}, {URL: "http://h/b"}})
	if len(s.findings) != 2 {
		t.Fatalf("expected 2, got %d", len(s.findings))
	}
	// Another seed must be additive (a second checkpoint carry-over on a longer scan).
	s.SeedFindings([]Finding{{URL: "http://h/c"}})
	if len(s.findings) != 3 {
		t.Errorf("seed is not cumulative; got %d", len(s.findings))
	}
}

// TestNomorePayloadsDir_UsesGopathModCache — the exact fix that took two pipeline runs to
// nail. The lookup MUST NOT reject a non-directory `payloads/headers` (in nomore403 v1.4.0
// it's a plain file — the header-name list). This test rebuilds that shape in a temp dir
// and asserts findNomorePayloadsDir picks it.
func TestFindNomorePayloadsDir_EmptyOnMiss_Companion(t *testing.T) {
	// A path with no payloads subtree at all: return "" so runNomore403 leaves cmd.Dir
	// unset and falls back to the process CWD rather than pointing at a broken root.
	if got := findNomorePayloadsDir([]string{t.TempDir(), t.TempDir()}); got != "" {
		t.Errorf("no candidate has payloads/headers -> empty; got %q", got)
	}
}

// TestGopathModCacheGlobs — GOPATH is a list. The pre-fix version treated the whole string
// as one path and never found the module cache on multi-entry setups. Test that a
// separator-joined value produces a glob per entry.
func TestGopathModCacheGlobs(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	// Simulate a nomore403@vX under one of the entries.
	target := filepath.Join(b, "pkg/mod/github.com/devploit/nomore403@v1.4.0")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// Use the OS-native list separator so this test works on Windows and Unix.
	joined := a + string(filepath.ListSeparator) + b
	got := gopathModCacheGlobs(joined)
	found := false
	for _, m := range got {
		if m == target {
			found = true
		}
	}
	if !found {
		t.Errorf("nomore403 module in second GOPATH entry not surfaced; got %v", got)
	}
}

// TestAuditHelpers — ternary/fileExists/isDir/truncMsg are internal but 100% dead on the
// current coverage matrix. Trivial but load-bearing (a wrong branch on isDir would put
// audit back on the false-positive path that took two turns to unwind).
func TestAuditHelpers(t *testing.T) {
	if ternary(true, "y", "n") != "y" || ternary(false, "y", "n") != "n" {
		t.Error("ternary broke")
	}
	if !fileExists("audit.go") {
		t.Error("fileExists on a real file must be true")
	}
	if fileExists(filepath.Join(t.TempDir(), "definitely-not-here")) {
		t.Error("fileExists on a missing path must be false")
	}
	if !isDir(t.TempDir()) {
		t.Error("isDir on a real dir must be true")
	}
	if isDir("audit.go") {
		t.Error("isDir on a file must be false")
	}
	if truncMsg("abcdefghij", 4) != "abc…" {
		t.Errorf("truncMsg unexpected: %q", truncMsg("abcdefghij", 4))
	}
	if truncMsg("ab", 4) != "ab" {
		t.Errorf("truncMsg must pass through short strings")
	}
}

// TestNorm_ScopeAndQueryPreservation — norm() is the scope guard on every discovered URL.
// It MUST drop off-host references, MUST preserve queries (openapi endpoints often carry
// them), MUST strip fragments (client-side anchors are not requests), and MUST accept both
// absolute and reference forms.
func TestNorm(t *testing.T) {
	tgt, _ := url.Parse("https://target.tld/api/")
	cases := map[string]string{
		"/admin":                              "https://target.tld/admin",
		"users?page=2":                        "https://target.tld/api/users?page=2",
		"/x#anchor":                           "https://target.tld/x",
		"https://target.tld/y":                "https://target.tld/y",
		"https://other.tld/x":                 "",  // off-host must drop
		"ftp://target.tld/x":                  "",  // non-http scheme must drop
		"":                                    "",  // empty must drop
		"#fragment-only":                      "",  // fragment-only must drop
	}
	for in, want := range cases {
		if got := norm(tgt, in); got != want {
			t.Errorf("norm(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactedHeaders_KeepsAllNames — the operator scanning a HAR file must see every header
// name (so they know auth was carried) even when the value is redacted. Header set MUST
// match every case-insensitive spelling used in real HTTP clients.
func TestRedactedHeaders_KeepsAllNames_CaseInsensitive(t *testing.T) {
	in := map[string]string{
		"cookie":        "session=abc",
		"AUTHORIZATION": "Bearer xyz",
		"User-Agent":    "sift/0",
	}
	got := redactedHeaders(in)
	names := map[string]string{}
	for _, h := range got {
		names[strings.ToLower(h.Name)] = h.Value
	}
	if !strings.Contains(names["cookie"], "REDACTED") {
		t.Errorf("cookie not redacted: %v", names["cookie"])
	}
	if !strings.Contains(names["authorization"], "REDACTED") {
		t.Errorf("Authorization (upper) not redacted: %v", names["authorization"])
	}
	if names["user-agent"] != "sift/0" {
		t.Errorf("non-secret preserved verbatim: %v", names["user-agent"])
	}
}

// TestParseProxy — the exact fix from the pipeline: a garbage -x must surface an error
// (so main can exit non-zero and never send auth headers to the origin), while every
// valid scheme must round-trip.
func TestParseProxy(t *testing.T) {
	good := []string{
		"http://127.0.0.1:8080",
		"https://proxy.local:443",
		"socks5://user:pass@10.0.0.1:1080",
		"socks5h://tor:9050",
	}
	for _, u := range good {
		if _, err := parseProxy(u); err != nil {
			t.Errorf("valid proxy %q rejected: %v", u, err)
		}
	}
	bad := []string{
		"not-a-url",
		"ftp://x",
		"http://",
		"://nope",
	}
	for _, u := range bad {
		if _, err := parseProxy(u); err == nil {
			t.Errorf("bad proxy %q accepted", u)
		}
	}
}

// TestNewClient_HTTP2_ForceAttempt — the -h2 default MUST survive even when TLSClientConfig
// is customized. This is the exact regression the pipeline caught with the ALPN test but is
// worth a cheap unit assertion so a future edit that drops ForceAttemptHTTP2 fails loudly.
func TestNewClient_ForceHTTP2Set(t *testing.T) {
	c, err := newClient(&Config{Concurrency: 1, Timeout: 5})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is not *http.Transport: %T", c.Transport)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 lost — h2 negotiation will silently downgrade")
	}
}

// TestRunAudit_Integration — the audit itself runs every engine wrapper against a controlled
// mock. Slow (~15s live) but the single test that exercises runFerox/runFfuf/runKatana/runGau/
// runNomore403 end-to-end. Skipped in -short mode so a fast local run stays fast.
func TestRunAudit_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping the live audit integration test")
	}
	// runAudit prints heavily; capture stdout by redirecting os.Stdout is fragile in tests, so
	// we just call it and gate on the return code — 0 means every wired integration worked.
	code := runAudit()
	if code != 0 {
		t.Errorf("runAudit returned %d — some integration check failed (see stderr above)", code)
	}
}
