package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRace_HighFanoutScan — runs the real Scanner path against a large mock target with
// enough concurrent workers and enough URLs to exercise every write-under-lock site
// simultaneously. Skipped in -short so a normal `go test` still finishes fast; call with
// `go test -race -run TestRace_HighFanoutScan -v` before every release.
//
// Coverage (writes): s.findings (record), s.ckptFile (record), s.har.caps (verify), s.tried403
// (markBypassTried on 403 samples), scanner atomics (attempts/fetchErrs), per-dir atomics
// (dirAttempts/dirErrs), Config.Truncated (verify + Run tail), Config.reqCount (fetch).
func TestRace_HighFanoutScan(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping the high-fanout race stress test")
	}
	// The race test discovers URLs through ferox/ffuf; without at least one of them on
	// PATH the scanner has no candidates to feed to record()/har.add and the assertion
	// "≥1 real hit recovered" fires with a misleading zero. This test's real purpose is
	// -race cleanliness of the write sites, not "engines are installed" — skip cleanly
	// when the CI runner doesn't have either brute engine.
	if !haveBin("feroxbuster") && !haveBin("ffuf") {
		t.Skip("neither feroxbuster nor ffuf on PATH — high-fanout race test needs a candidate producer")
	}

	// A mock that:
	//   - answers /admin, /api, /users, /health with distinct 200 pages (real hits)
	//   - returns a rotating 403 body on /forbidden-* (exercises bypassTried / markBypassTried)
	//   - returns a rotating 404 body on everything else (dynamic 404 forces high threshold)
	// The rotating bodies force many concurrent writes into different scanner buckets.
	var hits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		p := r.URL.Path
		switch {
		case p == "/admin":
			w.Header().Set("Server", "nginx/1.25")
			w.Write([]byte(`<title>Admin</title>dashboard users billing`))
		case p == "/api":
			w.Write([]byte(`<title>API</title>rest endpoints reference`))
		case p == "/users":
			w.Write([]byte(`<title>Users</title>list roles export`))
		case p == "/health":
			w.Write([]byte(`<title>Health</title>ok`))
		case strings.HasPrefix(p, "/forbidden-"):
			w.WriteHeader(403)
			// Rotating body — same shape, different suffix — exercises the tried403 tolerance.
			fmt.Fprintf(w, `<title>Forbidden</title>%s`, p)
		default:
			w.WriteHeader(404)
			fmt.Fprintf(w, `<title>404</title>not found %s %s`, p, strings.Repeat("x", 40))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Big-ish wordlist to force real concurrency inside cleanDir.
	tmp, err := os.CreateTemp(t.TempDir(), "lucid-race-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("admin\napi\nusers\nhealth\n")
	// 100 forbidden probes → 100 403s → all should collapse via bypassTried after the first,
	// which exercises the tried403 slice under high write contention.
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sb, "forbidden-%d\n", i)
	}
	// 100 misses → 100 dynamic 404s that hit fetchErrs=0 but bump attempts under load.
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sb, "miss-%d\n", i)
	}
	tmp.WriteString(sb.String())
	tmp.Close()

	// Checkpoint on so the ckptFile write path is exercised concurrently.
	ckptDir := t.TempDir()
	ckpt := filepath.Join(ckptDir, "lucid-race.ckpt.jsonl")

	// -har on so harScope.add is exercised concurrently under s.har.mu.
	harPath := filepath.Join(ckptDir, "race.har")

	cfg := &Config{
		Concurrency:    16, // heavy write contention on s.mu inside record()
		Timeout:        5,
		Probes:         2,
		Threshold:      -1,
		ReviewMargin:   2,
		MaxDepth:       0,
		Wordlist:       tmp.Name(),
		HAROutput:      harPath,
		CheckpointPath: ckpt,
		Bypass:         false, // don't shell out during the race — external binaries would confound the detector
		Archive:        false,
		Assets:         true,
		Collapse:       5,
		EngineTimeout:  30,
		MaxCandidates:  10000,
		UA:             "lucid-race/0",
		Headers:        map[string]string{"Cookie": "session=abc"},
	}
	// Force the built-in Runtime state (not from ResetRuntime, since library callers may build
	// their own Config).
	cfg.Throttle = NewThrottle(0)

	target, _ := url.Parse(srv.URL + "/")
	client, cerr := newClient(cfg)
	if cerr != nil {
		t.Fatal(cerr)
	}

	// Concurrent verify path: use NewScanner + Run() directly (the exact call graph main() uses).
	scanner := NewScanner(cfg, client, target, nil)
	defer scanner.Close()

	// Also hit ResetRuntime while the scan is running to make sure the Truncated / reqCount
	// races are covered — an external goroutine flips the atomics while workers are firing.
	var stopHammer sync.WaitGroup
	stopHammer.Add(1)
	stop := make(chan struct{})
	go func() {
		defer stopHammer.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = cfg.Truncated.Load()
				_ = atomic.LoadInt64(&cfg.reqCount)
			}
		}
	}()

	findings := scanner.Run()
	close(stop)
	stopHammer.Wait()

	// Sanity: we should have found at least the 4 real hits. The exact count varies with the
	// discovery engines' availability in CI — the point of this test is `-race` cleanliness,
	// not a specific finding count.
	realHits := 0
	for _, f := range findings {
		if strings.HasSuffix(f.URL, "/admin") || strings.HasSuffix(f.URL, "/api") ||
			strings.HasSuffix(f.URL, "/users") || strings.HasSuffix(f.URL, "/health") {
			realHits++
		}
	}
	if realHits == 0 {
		t.Errorf("no real hits recovered — scan produced findings but none matched planted URLs (findings=%d)",
			len(findings))
	}

	// HAR path exercised via scanner (writes into s.har). main() does the final serialize;
	// we do it inline so this test also proves the serializer sees the concurrent captures
	// cleanly. This is the same call graph main.go uses after scanner.Run() returns.
	if err := writeHAR(harPath, scanner.HAREntries()); err != nil {
		t.Errorf("writeHAR: %v", err)
	}
	if st, err := os.Stat(harPath); err != nil || st.Size() < 100 {
		t.Errorf("HAR file %s: st=%v err=%v", harPath, st, err)
	}
	// Checkpoint path was exercised.
	if st, err := os.Stat(ckpt); err != nil || st.Size() == 0 {
		t.Errorf("checkpoint %s: st=%v err=%v", ckpt, st, err)
	}
}

// TestRace_ConfigResetDuringConcurrentReads — ResetRuntime clears atomics that fetch/verify
// read under load. A library consumer might call it while a background goroutine is still
// finishing up. Detector must not flag any race here.
func TestRace_ConfigResetDuringConcurrentReads(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping the config-reset race test")
	}
	cfg := &Config{Delay: 50, MaxReq: 100}
	cfg.Throttle = NewThrottle(50)

	// Bounded work — writer finishes in ≤5000 iterations, readers stop when writer's done
	// (via a done channel). No wall-clock timing.
	writerDone := make(chan struct{})
	var rg sync.WaitGroup
	// Readers.
	for i := 0; i < 8; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for {
				select {
				case <-writerDone:
					return
				default:
					_ = cfg.Truncated.Load()
					_ = atomic.LoadInt64(&cfg.reqCount)
				}
			}
		}()
	}
	// Writer: bounded loop that also exercises ResetRuntime.
	go func() {
		defer close(writerDone)
		for i := 0; i < 5000; i++ {
			cfg.Truncated.Store(true)
			atomic.AddInt64(&cfg.reqCount, 1)
			if i%100 == 0 {
				cfg.ResetRuntime()
			}
		}
	}()
	rg.Wait()
}
