package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// If every calibration probe errors (server drops the connection), the profile must be flagged
// Unusable — otherwise judge() on an empty baseline flags every real candidate as VHit and the
// scan silently degrades into engine noise re-emitted as hits.
func TestCalibrate_AllProbesFailed_MarksUnusable(t *testing.T) {
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
	cfg := &Config{Probes: 4, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "lucid-test"}
	p := calibrate(mustNewClient(t, cfg), u, srv.URL+"/dir/", cfg)

	if !p.Unusable {
		t.Fatalf("all-failed calibration must be Unusable, got %+v", p)
	}
	if len(p.Sims) != 0 {
		t.Fatalf("expected zero probes stored, got %d", len(p.Sims))
	}
	// Sanity: the empty-baseline judge would (still) return VHit for anything — proving the guard
	// in the caller is what protects the scan.
	if v, _ := p.judge(Resp{Status: 200, Sim: 0xDEADBEEF}); v != VHit {
		t.Fatalf("empty-baseline judge returns %v; the Unusable flag is the only safety net", v)
	}
}

// A calibration where fewer than half the probes succeed can't measure the baseline spread —
// Threshold/Dynamic would be trained on one point. Mark it Unusable.
func TestCalibrate_TooFewSuccessfulProbes_MarksUnusable(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First probe answers; the rest are hijacked and closed.
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
			}
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 4, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "lucid-test"}
	p := calibrate(mustNewClient(t, cfg), u, srv.URL+"/dir/", cfg)

	if !p.Unusable {
		t.Fatalf("1-of-4 probes must be Unusable, got %+v", p)
	}
	if len(p.Sims) != 1 {
		t.Fatalf("expected 1 successful probe recorded, got %d", len(p.Sims))
	}
}

// An exhausted request budget must stop calibration immediately instead of chewing the budget
// on retries that can never succeed. Result: Unusable, no stored sims.
func TestCalibrate_BudgetExhausted_StopsAndMarksUnusable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 4, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "lucid-test", MaxReq: 1}
	// Pre-exhaust the budget so the very first probe returns errBudget.
	atomic.StoreInt64(&cfg.reqCount, 100)

	p := calibrate(mustNewClient(t, cfg), u, srv.URL+"/dir/", cfg)

	if !p.Unusable {
		t.Fatalf("budget-exhausted calibration must be Unusable, got %+v", p)
	}
	if len(p.Sims) != 0 {
		t.Fatalf("no probe should have succeeded, got %d sims", len(p.Sims))
	}
}

// A healthy calibration (all probes succeed) must NOT be flagged Unusable — regression guard so
// the new flag never triggers on real traffic.
func TestCalibrate_HealthyBaseline_NotUnusable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("<html><title>Not Found</title><body>missing</body></html>"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Probes: 3, Threshold: -1, ReviewMargin: 2, Timeout: 2, UA: "lucid-test"}
	p := calibrate(mustNewClient(t, cfg), u, srv.URL+"/dir/", cfg)

	if p.Unusable {
		t.Fatalf("healthy calibration must not be Unusable, got %+v", p)
	}
	if len(p.Sims) != 3 {
		t.Fatalf("expected 3 successful probes, got %d", len(p.Sims))
	}
}

// TestJudge_Status101_VHit — a 101 Switching Protocols is a WebSocket
// handshake success and cannot ever be a soft-404, no matter what the
// calibrated envelope looks like. judge() must promote it to VHit
// unconditionally so verify()'s ws-probe promotion isn't swallowed by a
// permissive baseline (e.g. a dir where 101 somehow landed in Statuses).
func TestJudge_Status101_VHit(t *testing.T) {
	// A pathological profile whose Statuses set includes 101 AND whose Sims
	// contain the empty-body simhash (0). Pre-fix the first branch would let
	// 101 fall through to the simhash check, where an empty-body 101 (which
	// is what a real handshake looks like — no body) would land at distance 0
	// and be classed VNotFound.
	p := Profile{
		Statuses:    map[int]bool{101: true, 404: true},
		Titles:      map[string]bool{"": true},
		TitleStable: true,
		Sims:        []uint64{0},
		Threshold:   4,
		Margin:      2,
	}
	v, dist := p.judge(Resp{Status: 101, Sim: 0})
	if v != VHit {
		t.Fatalf("101 handshake must be VHit unconditionally, got %v (dist=%d)", v, dist)
	}
	if dist != 64 {
		t.Fatalf("101 branch must report max distance 64, got %d", dist)
	}
}
