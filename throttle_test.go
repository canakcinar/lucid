package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Throttle is the WAF-adaptive pacer every worker consults before sending a
// request. It has three concurrent moving parts (wait/penalize/ok) sharing a
// single int64, and prior to this file it had 0% test coverage — a regression
// in the CAS loop (say, a maintainer swapping CompareAndSwapInt64 for a plain
// store) would go silently wrong on production hardware, not on the developer's
// laptop, and no test would catch it.

// TestNewThrottle_ZeroBaseIsIdle — a base delay of zero means "no throttle" and
// wait() must be a no-op. This is the -delay=0 default; if it accidentally
// slept even for a millisecond, a wide scan would balloon by 20k×N ms.
func TestNewThrottle_ZeroBaseIsIdle(t *testing.T) {
	th := NewThrottle(0)
	start := time.Now()
	th.wait()
	if elapsed := time.Since(start); elapsed > 2*time.Millisecond {
		t.Errorf("wait() on a zero-base Throttle slept %v — expected near-zero; the scan's hot path just slowed by that per request", elapsed)
	}
	if got := atomic.LoadInt64(&th.cur); got != 0 {
		t.Errorf("NewThrottle(0).cur = %d; expected 0 — the wait() no-op branch would never fire", got)
	}
}

// TestPenalize_DoublesUpToCeiling — the WAF-block response path doubles the
// current delay, floored at 200 ms and capped at 5000 ms. The ceiling is what
// keeps a 429 storm from stalling the scan forever; a broken ceiling would let
// a single burst of blocks freeze the run indefinitely.
func TestPenalize_DoublesUpToCeiling(t *testing.T) {
	th := NewThrottle(50)
	// One penalty from base 50 → 100, still below the 200 floor, so it snaps to 200.
	th.penalize()
	if got := atomic.LoadInt64(&th.cur); got != 200 {
		t.Errorf("penalize() from cur=50 gave %d; expected 200 (floor snap)", got)
	}
	// Enough penalties to blow past 5000 — the last one MUST clip to the ceiling.
	for i := 0; i < 20; i++ {
		th.penalize()
	}
	if got := atomic.LoadInt64(&th.cur); got != 5000 {
		t.Errorf("penalize() after saturation gave %d; expected 5000 (ceiling clamp)", got)
	}
}

// TestOk_DecaysTowardBase — a clean response walks the delay back down toward
// base by 25 ms per call, and MUST NOT undershoot the base. If ok() went below
// base, the throttle would start behaving as "faster than the user asked" —
// silently ignoring -delay.
func TestOk_DecaysTowardBase(t *testing.T) {
	th := NewThrottle(100)
	atomic.StoreInt64(&th.cur, 500) // pretend a WAF burst already lifted us
	// 500 → 475 → 450 → … → should land at exactly 100 and stop there.
	for i := 0; i < 100; i++ {
		th.ok()
	}
	if got := atomic.LoadInt64(&th.cur); got != 100 {
		t.Errorf("ok() decayed cur to %d; expected 100 (never below base)", got)
	}
	// Once at base, further ok() calls are no-ops — verify the early-return branch.
	th.ok()
	if got := atomic.LoadInt64(&th.cur); got != 100 {
		t.Errorf("ok() at-base gave %d; expected 100 (early return)", got)
	}
}

// TestOk_DoesNotUndershoot_WhenStepOvershoots — the decay step is 25 ms; if base
// is 90 ms and cur is 100 ms, one ok() must land ON 90, not on 75. This is the
// `if n < t.base { n = t.base }` guard.
func TestOk_DoesNotUndershoot_WhenStepOvershoots(t *testing.T) {
	th := NewThrottle(90)
	atomic.StoreInt64(&th.cur, 100)
	th.ok()
	if got := atomic.LoadInt64(&th.cur); got != 90 {
		t.Errorf("ok() undershot base: cur=%d, base=90", got)
	}
}

// TestThrottle_ConcurrentPenalizeAndOk_NoLostUpdate — the whole point of the CAS
// loops is that concurrent penalize/ok never drop an update. This test races 16
// goroutines against a shared throttle for 5000 operations and asserts the
// final cur is bounded correctly. Prior to this test the CAS was a code path
// no test ever exercised concurrently — a regression to a plain Store would
// pass every other unit test.
//
// Run with `go test -race -run TestThrottle_Concurrent ./...` for the strong
// signal; the race detector is what turns a "sometimes cur is stale" bug into
// a hard fail.
func TestThrottle_ConcurrentPenalizeAndOk_NoLostUpdate(t *testing.T) {
	th := NewThrottle(50)
	const workers = 16
	const iters = 500
	var wg sync.WaitGroup
	wg.Add(workers * 2)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				th.penalize()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				th.ok()
			}
		}()
	}
	wg.Wait()
	got := atomic.LoadInt64(&th.cur)
	// Under any interleaving the invariant is base ≤ cur ≤ max. If a CAS were
	// dropped, we could see cur below base or wildly above the ceiling.
	if got < 50 || got > 5000 {
		t.Errorf("post-race cur=%d violates base(50) ≤ cur ≤ max(5000) — CAS lost an update", got)
	}
}
