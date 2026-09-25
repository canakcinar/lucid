package main

import (
	"sync/atomic"
	"time"
)

// Throttle is a WAF-adaptive pacer shared by all workers. Every request waits the current
// delay; a block signal (429/503) doubles it, a clean response decays it back toward the base.
type Throttle struct {
	base int64 // ms floor
	cur  int64 // ms current (atomic)
	max  int64 // ms ceiling
}

func NewThrottle(baseMs int) *Throttle {
	b := int64(baseMs)
	return &Throttle{base: b, cur: b, max: 5000}
}

func (t *Throttle) wait() {
	if d := atomic.LoadInt64(&t.cur); d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
}

func (t *Throttle) penalize() {
	for {
		c := atomic.LoadInt64(&t.cur)
		n := c * 2
		if n < 200 {
			n = 200
		}
		if n > t.max {
			n = t.max
		}
		if atomic.CompareAndSwapInt64(&t.cur, c, n) {
			return
		}
	}
}

func (t *Throttle) ok() {
	for {
		c := atomic.LoadInt64(&t.cur)
		if c <= t.base {
			return
		}
		n := c - 25
		if n < t.base {
			n = t.base
		}
		if atomic.CompareAndSwapInt64(&t.cur, c, n) {
			return
		}
	}
}
