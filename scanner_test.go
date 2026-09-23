package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestVerify_FetchError_CountsAndReturnsNoFinding — a single verify() whose fetch errors
// (WAF-level connection reset, DNS blip, TLS handshake regression) must bump BOTH the per-dir
// and scanner-wide error counters and produce no Finding. Before the fix the counters didn't
// exist: a total mid-scan network failure showed up as "0 findings, coverage: complete".
func TestVerify_FetchError_CountsAndReturnsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("hijacker unsupported")
		}
		c, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		c.Close() // drop mid-response -> fetch returns Err
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	// A calibration profile that would otherwise accept any 200 as VHit — proves verify
	// bails on r.Err BEFORE judge(), and does so through the counters, not silently.
	p := Profile{Statuses: map[int]bool{200: true}, Titles: map[string]bool{"": true}, TitleStable: true}

	var dirAttempts, dirErrs atomic.Int64
	s.verify(cand{url: srv.URL + "/x", source: "test"}, p, &dirAttempts, &dirErrs)

	if got := dirAttempts.Load(); got != 1 {
		t.Fatalf("dirAttempts=%d want 1", got)
	}
	if got := dirErrs.Load(); got != 1 {
		t.Fatalf("dirErrs=%d want 1 (r.Err must be counted)", got)
	}
	if got := s.attempts.Load(); got != 1 {
		t.Fatalf("scanner.attempts=%d want 1", got)
	}
	if got := s.fetchErrs.Load(); got != 1 {
		t.Fatalf("scanner.fetchErrs=%d want 1", got)
	}
	if len(s.findings) != 0 {
		t.Fatalf("expected no findings on fetch error, got %d", len(s.findings))
	}
}

// TestVerify_OffScope_NotCountedAsError — an off-host redirect is expected, not blindness.
// Only r.Err bumps fetchErrs; OffScope bumps attempts (a request was made) but must not
// flip the "network is broken" signal.
func TestVerify_OffScope_NotCountedAsError(t *testing.T) {
	// The target host: it serves a 302 to some OTHER host, which fetch() flags OffScope.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://other.invalid.example/")
		w.WriteHeader(302)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)
	p := Profile{Statuses: map[int]bool{200: true}, Titles: map[string]bool{"": true}, TitleStable: true}

	var dirAttempts, dirErrs atomic.Int64
	s.verify(cand{url: srv.URL + "/x", source: "test"}, p, &dirAttempts, &dirErrs)

	if got := dirAttempts.Load(); got != 1 {
		t.Fatalf("dirAttempts=%d want 1 (off-scope still counts as an attempt)", got)
	}
	if got := dirErrs.Load(); got != 0 {
		t.Fatalf("dirErrs=%d want 0 (off-scope is not a network failure)", got)
	}
	if got := s.fetchErrs.Load(); got != 0 {
		t.Fatalf("scanner.fetchErrs=%d want 0", got)
	}
}

// TestCleanDir_AllFetchErrors_FlipsTruncated — when every attempted fetch in a dir errors
// (network dead for that prefix), cleanDir must set cfg.Truncated so the final report reads
// "coverage: PARTIAL" instead of the misleading "coverage: complete, 0 findings".
func TestCleanDir_AllFetchErrors_FlipsTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
			}
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 2}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	// Non-wall profile so every candidate goes through verify() (not the wall shortcut).
	p := Profile{Statuses: map[int]bool{200: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	cands := []cand{
		{url: srv.URL + "/a", source: "test"},
		{url: srv.URL + "/b", source: "test"},
		{url: srv.URL + "/c", source: "test"},
	}

	s.cleanDir(srv.URL+"/", cands, p)

	if !cfg.Truncated.Load() {
		t.Fatal("cfg.Truncated must flip when every candidate in the dir fails to fetch")
	}
	if len(s.findings) != 0 {
		t.Fatalf("no findings expected on all-error dir, got %d", len(s.findings))
	}
	if got := s.fetchErrs.Load(); got != 3 {
		t.Fatalf("scanner.fetchErrs=%d want 3", got)
	}
}

// TestCleanDir_HealthyDir_DoesNotFlipTruncated — regression guard: a dir where fetches
// succeed must NOT set Truncated, even when the candidates aren't findings.
func TestCleanDir_HealthyDir_DoesNotFlipTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 2}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	p := Profile{Statuses: map[int]bool{404: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	cands := []cand{
		{url: srv.URL + "/a", source: "test"},
		{url: srv.URL + "/b", source: "test"},
	}

	s.cleanDir(srv.URL+"/", cands, p)

	if cfg.Truncated.Load() {
		t.Fatal("cfg.Truncated must NOT flip on a healthy dir with no fetch errors")
	}
	if got := s.fetchErrs.Load(); got != 0 {
		t.Fatalf("scanner.fetchErrs=%d want 0", got)
	}
}

// TestNewScanner_ClampsNonPositiveConcurrency — cleanDir spawns exactly cfg.Concurrency
// workers and then sends on an unbuffered channel; with Concurrency<=0 no reader exists,
// the first non-wall candidate blocks forever, and the entire scan deadlocks. NewScanner
// must clamp Concurrency (and Probes) to >=1 so a `-c 0`, a missed default in a library
// caller, or a future flag typo cannot wedge the tool.
func TestNewScanner_ClampsNonPositiveConcurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	for _, c := range []int{0, -1, -100} {
		cfg := &Config{Probes: 0, Threshold: -1, ReviewMargin: 2, Timeout: 2,
			UA: "sift-test", Concurrency: c}
		client := mustNewClient(t, cfg)
		s := NewScanner(cfg, client, u, nil)
		if cfg.Concurrency < 1 {
			t.Fatalf("Concurrency=%d not clamped (got %d)", c, cfg.Concurrency)
		}
		if cfg.Probes < 1 {
			t.Fatalf("Probes not clamped (got %d)", cfg.Probes)
		}

		// End-to-end proof the clamp actually saves cleanDir from hanging: run cleanDir on
		// a non-wall profile (so candidates hit the channel path, not the wall shortcut) in
		// a goroutine and require it to return. Before the clamp this would block forever.
		p := Profile{Statuses: map[int]bool{404: true}, Titles: map[string]bool{"": true}, TitleStable: true}
		cands := []cand{{url: srv.URL + "/a", source: "test"}}
		done := make(chan struct{})
		go func() {
			s.cleanDir(srv.URL+"/", cands, p)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("cleanDir hung with original Concurrency=%d — clamp did not take effect", c)
		}
	}
}

// TestScanner_ShellDetection_ThroughRootRedirect — regression for the redirect-fronted
// SPA blind spot. When `/` answers with an empty-bodied 3xx (SPA behind `/app/`, SSO
// portal at `/login`, locale router at `/en/`), the pre-fix Run() left baseSim=0 —
// SimHash("") — and the shell guard `s.baseSim != 0 && ...` in verify() silently
// disabled kind:shell tagging for every SPA route, so each 200 shell payload was
// emitted as a distinct finding. followShellHop must follow one on-host hop so
// baseSim carries the real shell signature; a same-body route below the redirect
// target must then be tagged kind:shell.
func TestScanner_ShellDetection_ThroughRootRedirect(t *testing.T) {
	// Shell body large and structured enough for SimHash to yield a stable non-zero fingerprint.
	shell := `<!doctype html><html><head><title>App</title></head><body>` +
		`<div id="root">SPA shell content — client renders here. ` +
		strings.Repeat("token ", 40) + `</div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Location", "/app/")
			w.WriteHeader(302)
			return
		case strings.HasPrefix(r.URL.Path, "/app"):
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(shell))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	// Reproduce Run()'s shell probe: fetch `/`, then follow one on-host hop. Without
	// followShellHop, base.Sim would be SimHash("") = 0 and s.baseSim would silently
	// disable the shell tag in verify(). With the fix, base.Sim carries the shell body.
	rawBase := fetch(client, u, u.String(), cfg)
	if rawBase.Status != 302 {
		t.Fatalf("mock root did not redirect: status=%d", rawBase.Status)
	}
	if rawBase.Sim != 0 {
		t.Fatalf("empty-bodied 3xx must SimHash to 0, got %d — mock body leak", rawBase.Sim)
	}
	base := followShellHop(client, u, rawBase, cfg)
	if base.Sim == 0 {
		t.Fatal("followShellHop did not follow root redirect: baseSim=0 would disable shell detection")
	}
	if base.Status != 200 {
		t.Fatalf("followShellHop should have loaded /app/: status=%d", base.Status)
	}
	s.baseSim = base.Sim

	// verify /app/x with a non-wall profile so the candidate flows through the tagging path.
	// Same shell body -> Hamming(r.Sim, s.baseSim) <= 4 -> Kind must be "shell".
	p := Profile{Statuses: map[int]bool{404: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	var da, de atomic.Int64
	s.verify(cand{url: srv.URL + "/app/x", source: "test"}, p, &da, &de)

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding for /app/x, got %d", len(s.findings))
	}
	if s.findings[0].Kind != "shell" {
		t.Fatalf("Kind=%q, want %q — every SPA route would ship as a distinct finding",
			s.findings[0].Kind, "shell")
	}
}

// TestFollowShellHop_OffScopeRedirectNotFollowed — auth-header no-leak invariant.
// A root that redirects cross-host (SSO handoff to another domain) must NOT be
// followed, because cfg.Headers / cfg.Proxy credentials are scoped to the target
// host. followShellHop must return the original response unchanged; baseSim stays 0.
func TestFollowShellHop_OffScopeRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://other.invalid.example/login")
		w.WriteHeader(302)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)

	raw := fetch(client, u, u.String(), cfg)
	if !raw.OffScope {
		t.Fatalf("mock cross-host redirect must be flagged OffScope")
	}
	got := followShellHop(client, u, raw, cfg)
	if got.Sim != 0 || got.Status != 302 {
		t.Fatalf("off-scope redirect must not be followed: status=%d sim=%d", got.Status, got.Sim)
	}
}

// TestCleanDir_WallShortcut_RespectsSkip — resume contract: a URL the previous run
// already emitted (loaded into skip{}) MUST NOT reappear in this pass, including as a
// member of a wall Finding. Before the fix cleanDir's wall shortcut appended c.url to
// the wall bucket without consulting s.skip, so a --resume run against a walled site
// re-emitted the exact URLs the operator had already seen. This regression-guards it.
func TestCleanDir_WallShortcut_RespectsSkip(t *testing.T) {
	// Server that returns 403 for everything — pairs with a static-403 Profile below so
	// wallOf(p) reports isWall=true and the shortcut path is exercised.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 2}
	client := mustNewClient(t, cfg)

	// Seed skip{} with one URL — a resume boundary carrying it over from the previous run.
	skipped := srv.URL + "/already-seen"
	fresh := srv.URL + "/new"
	s := NewScanner(cfg, client, u, map[string]bool{skipped: true})

	// Static-403 profile — wallOf() returns (403, true) so both cands take the wall shortcut.
	p := Profile{Statuses: map[int]bool{403: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	cands := []cand{
		{url: skipped, source: "test", status: 403},
		{url: fresh, source: "test", status: 403},
	}

	s.cleanDir(srv.URL+"/", cands, p)

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 wall Finding, got %d", len(s.findings))
	}
	f := s.findings[0]
	if f.Type != "uniform-wall" {
		t.Fatalf("Finding.Type=%q want uniform-wall", f.Type)
	}
	// The skipped URL must not appear anywhere in the Finding — not as representative,
	// not as a Member. The fresh URL must be there.
	if f.URL == skipped {
		t.Fatalf("wall representative is the skipped URL %q — --resume contract broken", skipped)
	}
	for _, m := range f.Members {
		if m == skipped {
			t.Fatalf("skipped URL %q reappeared in wall Members %v", skipped, f.Members)
		}
	}
	sawFresh := false
	for _, m := range f.Members {
		if m == fresh {
			sawFresh = true
		}
	}
	if !sawFresh {
		t.Fatalf("fresh URL %q missing from wall Members %v", fresh, f.Members)
	}
	if f.Collapsed != 1 {
		t.Fatalf("Finding.Collapsed=%d want 1 (only the fresh URL)", f.Collapsed)
	}
}

// TestVerify_SSE_TaggedKindSSE — an endpoint that answers a plain GET with
// text/event-stream is a Server-Sent Events channel. Pre-fix, verify() only
// recorded CType and emitted no Kind, so /events and /stream ended up
// indistinguishable from any other 200 page. verify() must now tag Kind="sse".
func TestVerify_SSE_TaggedKindSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("data: hello\n\n"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	// Baseline expects 404 — so a 200 already flips VHit through the status branch;
	// the point of the test is Kind, not the verdict itself.
	p := Profile{Statuses: map[int]bool{404: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	var da, de atomic.Int64
	s.verify(cand{url: srv.URL + "/events", source: "test"}, p, &da, &de)

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding for SSE endpoint, got %d", len(s.findings))
	}
	if s.findings[0].Kind != "sse" {
		t.Fatalf("Kind=%q want %q — SSE stream indistinguishable from a page",
			s.findings[0].Kind, "sse")
	}
}

// TestVerify_WS_TaggedKindWS — an endpoint that speaks WebSocket answers a
// plain GET with 400/426 (or a naked hello page) and only reveals itself on
// the same URL after an Upgrade handshake. verify() must fire wsProbe when
// the URL path names a WS convention, and, on a 101 handshake, override
// r.Status=101 and tag Kind="ws". Pre-fix these endpoints were invisible.
func TestVerify_WS_TaggedKindWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("hijacker unsupported")
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
				"\r\n")
			_ = buf.Flush()
			return
		}
		// Plain GET without Upgrade: naked 400 (typical WS gateway behavior).
		w.WriteHeader(400)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 1, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	s := NewScanner(cfg, client, u, nil)

	// Baseline says 404 is not-found; the probe GET returns 400, which would already
	// trip a hit — but the point is the WS-probe promotion path and Kind.
	p := Profile{Statuses: map[int]bool{404: true}, Titles: map[string]bool{"": true}, TitleStable: true}
	var da, de atomic.Int64
	s.verify(cand{url: srv.URL + "/ws", source: "test"}, p, &da, &de)

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding for /ws, got %d", len(s.findings))
	}
	f := s.findings[0]
	if f.Kind != "ws" {
		t.Fatalf("Kind=%q want %q — /ws endpoint invisible without WS-probe promotion", f.Kind, "ws")
	}
	if f.Status != 101 {
		t.Fatalf("Status=%d want 101 — WS probe must override r.Status on handshake", f.Status)
	}
}
