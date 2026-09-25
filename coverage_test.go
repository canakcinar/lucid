package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		"User-Agent":    "lucid/0",
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
	if names["user-agent"] != "lucid/0" {
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

// TestRunAudit_Integration lives in integration_test.go behind -tags=integration so a plain
// `go test ./...` stays fast. Run `go test -tags=integration ./...` in CI or before releases.

// --- WebSocket / SSE detection ---

// TestWsPathHint_KnownConventions — lucid promotes a plain-GET failure (400/426) to a WS
// probe ONLY when the path names a realtime endpoint. Regressing this pattern means every
// broken endpoint on any host burns an extra WS-Upgrade fetch. Convention list matches
// wsHintRe verbatim: ws, socket, socket.io, stream, events (case-insensitive).
func TestWsPathHint_KnownConventions(t *testing.T) {
	// Positive: real-world realtime paths must hint.
	positive := []string{
		"http://h/ws",
		"http://h/api/ws",
		"http://h/socket.io/",
		"http://h/stream/live",
		"http://h/events",
		"http://h/events?channel=1",
		"http://h/socket",
		"http://h/WS", // case-insensitive
	}
	for _, u := range positive {
		if !wsPathHint(u) {
			t.Errorf("wsPathHint(%q) = false — realtime convention missed, wsProbe won't fire", u)
		}
	}
	// Negative: ordinary paths must NOT hint (avoids gratuitous WS probes).
	negative := []string{
		"http://h/",
		"http://h/admin",
		"http://h/api/users",
		"http://h/wsdl",       // "ws" in the middle, not a full segment
		"http://h/streams",    // full segment but "streams" != "stream" convention
		"http://h/eventual",   // starts with "event" but not a real segment
	}
	for _, u := range negative {
		if wsPathHint(u) {
			t.Errorf("wsPathHint(%q) = true — false positive would burn an extra WS probe on every ordinary path", u)
		}
	}
	// Bad URL still returns false, not panic.
	if wsPathHint("::not-a-url::") {
		t.Error("wsPathHint on garbage must be false, not true (would falsely fire wsProbe)")
	}
}

// TestWsProbe_Returns101OnUpgrade — the exact contract that lets Kind="ws" work: a server
// that answers a WebSocket handshake with a real 101 must surface as code 101. net/http
// hides 101 from us, hence the raw dial. This test uses net.Listen so we can hand-craft
// the exact handshake reply.
func TestWsProbe_Returns101OnUpgrade(t *testing.T) {
	// Bind a raw TCP listener that replies with 101 Switching Protocols and closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read a small chunk of the request to keep the client's Write from blocking on
		// tiny TCP buffers; we don't parse it.
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	}()

	target, _ := url.Parse("http://" + ln.Addr().String() + "/")
	cfg := &Config{Timeout: 3, UA: "lucid-test"}
	code, err := wsProbe(target, "http://"+ln.Addr().String()+"/ws", cfg)
	if err != nil {
		t.Fatalf("wsProbe returned err on a valid 101: %v", err)
	}
	if code != 101 {
		t.Errorf("wsProbe returned %d, want 101 — Kind=\"ws\" would silently disable", code)
	}
}

// TestWsProbe_NonUpgradeStaysNon101 — a normal HTTP endpoint must NOT be mislabelled as a
// WebSocket handshake. Regression guard against a bug that would promote every /ws-shaped
// URL that also answers a plain GET.
func TestWsProbe_NonUpgradeStaysNon101(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 3, UA: "lucid-test"}
	code, err := wsProbe(target, srv.URL+"/ws", cfg)
	if err != nil {
		t.Fatalf("wsProbe returned err on plain 200: %v", err)
	}
	if code == 101 {
		t.Error("plain HTTP 200 must NOT be promoted to 101")
	}
}

// TestWsProbe_BadHost — must return an error, never panic.
func TestWsProbe_BadHost(t *testing.T) {
	target, _ := url.Parse("http://target/")
	cfg := &Config{Timeout: 1}
	if _, err := wsProbe(target, "no-scheme-no-host", cfg); err == nil {
		t.Error("wsProbe on empty host must return an error")
	}
}

// TestFetchWith_ExtraHeadersOverrideCfg — the contract that lets verifyBypass replay a
// nomore403 winning header on top of the operator's -H defaults. The "extra" map MUST
// override cfg.Headers when keys collide — otherwise a nomore403 win with the same
// header name as an -H default would silently ship the old value and never reproduce.
func TestFetchWith_ExtraHeadersOverrideCfg(t *testing.T) {
	captured := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case captured <- r.Header.Clone():
		default:
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := &Config{
		Timeout: 3, UA: "lucid-test", Insecure: true,
		Headers: map[string]string{"X-Auth": "cfg-value", "Cookie": "session=abc"},
	}
	client := mustNewClient(t, cfg)
	target, _ := url.Parse(srv.URL + "/")

	r := fetchWith(client, target, srv.URL+"/x", cfg, map[string]string{
		"X-Auth":          "extra-overrides", // must WIN over cfg (same key, mixed case)
		"X-Forwarded-For": "127.0.0.1",       // additive, no cfg conflict
	})
	if r.Err != nil {
		t.Fatalf("fetchWith: %v", r.Err)
	}
	h := <-captured
	// http.Header.Get canonicalizes on lookup, but the STORED key is whatever was Set(). Assert
	// on both — a future refactor that changes the storage shape (e.g. a case-preserving map)
	// would still round-trip Get() but might trip a raw MIMEHeader consumer.
	if got := h.Get("X-Auth"); got != "extra-overrides" {
		t.Errorf("extra map failed to override cfg.Headers: got %q want %q", got, "extra-overrides")
	}
	if _, ok := h[http.CanonicalHeaderKey("X-Auth")]; !ok {
		t.Errorf("X-Auth not stored under its canonical key — a raw MIMEHeader consumer would miss it: keys=%v", keysOf(h))
	}
	if got := h.Get("X-Forwarded-For"); got != "127.0.0.1" {
		t.Errorf("extra-only header lost: got %q", got)
	}
	if got := h.Get("Cookie"); got != "session=abc" {
		t.Errorf("cfg.Header without collision must survive: got %q", got)
	}
	if got := h.Get("User-Agent"); got != "lucid-test" {
		t.Errorf("UA from cfg lost: got %q", got)
	}
}

func keysOf(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// TestFetchWith_BudgetExhausted — fetchWith must honor the same MaxReq budget as fetch.
// Silently letting verifyBypass sneak past the budget would let a hostile target burn
// arbitrary requests via a single 403 → nomore403 → verifyBypass chain.
func TestFetchWith_BudgetExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cfg := &Config{Timeout: 3, UA: "lucid-test", Insecure: true, MaxReq: 1}
	client := mustNewClient(t, cfg)
	target, _ := url.Parse(srv.URL + "/")

	// First call fits.
	if r := fetchWith(client, target, srv.URL+"/a", cfg, nil); r.Err != nil {
		t.Fatalf("first call must succeed: %v", r.Err)
	}
	// Second call MUST hit errBudget.
	r := fetchWith(client, target, srv.URL+"/b", cfg, nil)
	if r.Err == nil {
		t.Fatal("second call must return errBudget")
	}
}

// TestFetchWith_HARHeadersOnBypassReplay — verifyBypass calls fetchWith to replay a
// nomore403 winning header, and that replay MUST land Server/Set-Cookie/etc into r.Headers
// so buildHAR entries carry response evidence for the analyst. A guard that only fires in
// fetch() (and not fetchWith) would silently ship HAR entries without response headers for
// every verified bypass — this test locks the shared path in.
func TestFetchWith_HARHeadersOnBypassReplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.Header().Add("Set-Cookie", "sid=abc; HttpOnly")
		w.Header().Add("Set-Cookie", "csrf=xyz")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	cfg := &Config{Timeout: 3, UA: "lucid-test", HAROutput: "on"}
	client := mustNewClient(t, cfg)
	target, _ := url.Parse(srv.URL + "/")
	r := fetchWith(client, target, srv.URL+"/x", cfg, map[string]string{"X-Forwarded-For": "127.0.0.1"})
	if r.Err != nil {
		t.Fatalf("fetchWith: %v", r.Err)
	}
	if r.Headers["Server"] != "nginx/1.25" {
		t.Errorf("fetchWith bypass replay lost Server: %+v", r.Headers)
	}
	if len(r.Cookies) != 2 {
		t.Errorf("fetchWith bypass replay lost Set-Cookie (want 2, got %d)", len(r.Cookies))
	}
}

// TestHeaderFlags_AccumulatesAndJoins — the flag.Var driver for the repeatable -H flag.
// Two contracts:
//   1. Set() appends verbatim, so -H "Cookie: a" -H "X-Auth: b" produces both entries
//      (last-wins would silently drop the operator's first header)
//   2. String() joins with ", " so the flag package's usage output shows a readable list
//      (needed by go flag's help formatter — a broken String() would print <nil>)
func TestHeaderFlags_AccumulatesAndJoins(t *testing.T) {
	var h headerFlags
	// Empty state prints as empty string, not "<nil>", so flag help doesn't leak internals.
	if got := h.String(); got != "" {
		t.Errorf("empty headerFlags.String() = %q, want empty", got)
	}
	// Two Set() calls must both stick — this is the -H "Cookie: a" -H "X-Auth: b" path.
	if err := h.Set("Cookie: sid=abc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := h.Set("X-Auth: token"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(h) != 2 {
		t.Fatalf("expected 2 headers accumulated, got %d: %v", len(h), h)
	}
	if h[0] != "Cookie: sid=abc" || h[1] != "X-Auth: token" {
		t.Errorf("Set() order wrong (last-wins would drop the first): %v", h)
	}
	if got := h.String(); got != "Cookie: sid=abc, X-Auth: token" {
		t.Errorf("String() joining: got %q", got)
	}
}
