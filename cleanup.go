package main

import (
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
)

// Profile is the "what not-found looks like" fingerprint for ONE directory. Calibrating per
// directory matters: /api/ and /static/ often have different 404 behavior on the same host.
type Profile struct {
	Statuses    map[int]bool
	Sims        []uint64
	Titles      map[string]bool
	TitleStable bool // all calibration probes shared one title -> title is a reliable signal
	Threshold   int
	Margin      int // review-band width just inside the threshold
	Dynamic     bool
	Unusable    bool // too few successful probes -> baseline can't judge; caller must drop the dir
}

// Verdict is the three-way outcome of judging a candidate against a directory's not-found profile.
type Verdict int

const (
	VHit      Verdict = iota // clearly a real page
	VReview                  // borderline: near the not-found envelope, surface for the human
	VNotFound                // confidently a soft-404, drop
)

func randToken() string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = cs[rand.Intn(len(cs))]
	}
	return "zz" + string(b)
}

// calibrate probes cfg.Probes random non-existent paths in dir and learns the not-found
// profile. The intra-baseline spread (how much the probes differ from each other) drives an
// adaptive threshold: a dynamic 404 page widens the tolerance automatically.
func calibrate(client *http.Client, target *url.URL, dir string, cfg *Config) Profile {
	p := Profile{Statuses: map[int]bool{}, Titles: map[string]bool{}, Margin: cfg.ReviewMargin}
	base := strings.TrimSuffix(dir, "/") + "/"
	ok := 0
	for i := 0; i < cfg.Probes; i++ {
		r := fetch(client, target, base+randToken(), cfg)
		if r.Err != nil {
			// Budget exhaustion is terminal — stop chewing through it on a directory we can't finish.
			if errors.Is(r.Err, errBudget) {
				break
			}
			continue
		}
		ok++
		p.Statuses[r.Status] = true
		p.Sims = append(p.Sims, r.Sim)
		p.Titles[r.Title] = true
	}
	// Need at least half the requested probes (min 1) — a lone sample can't measure the intra-baseline
	// spread that Dynamic/Threshold depend on, and an empty baseline makes judge() flag everything.
	minOK := cfg.Probes / 2
	if minOK < 1 {
		minOK = 1
	}
	if ok < minOK {
		p.Unusable = true
	}
	p.TitleStable = len(p.Titles) == 1
	maxd := 0
	for i := 0; i < len(p.Sims); i++ {
		for j := i + 1; j < len(p.Sims); j++ {
			if d := Hamming(p.Sims[i], p.Sims[j]); d > maxd {
				maxd = d
			}
		}
	}
	p.Dynamic = maxd > simhashDynamicSpread
	if cfg.Threshold >= 0 {
		p.Threshold = cfg.Threshold
	} else {
		p.Threshold = maxd + simhashThresholdMargin // auto: cover the observed spread, plus margin
	}
	return p
}

// isNotFound is the strict SimHash+status test (no title/review logic) used to validate bypass
// responses, where titles aren't collected.
func (p Profile) isNotFound(r Resp) bool {
	if !p.Statuses[r.Status] {
		return false
	}
	for _, s := range p.Sims {
		if Hamming(r.Sim, s) <= p.Threshold {
			return true
		}
	}
	return false
}

// judge classifies a candidate three ways:
//   - status class new                              -> VHit
//   - title stable in baseline AND this title new   -> VHit (a distinct title is a real page)
//   - body farther than threshold                   -> VHit
//   - body just inside threshold (within Margin)    -> VReview (surfaced, not trusted)
//   - body deep inside the not-found envelope       -> VNotFound (dropped)
//
// The title override and review band exist so a real page that shares the site template with the
// 404 (thin/placeholder pages, wide dynamic thresholds) isn't silently discarded.
// judge also returns the SimHash distance to the nearest not-found sample — an evidence/confidence
// signal (higher = more distinct from "not found"). 64 means a status-class or title-based hit.
func (p Profile) judge(r Resp) (Verdict, int) {
	// A 101 Switching Protocols is a WebSocket handshake success — it can never
	// be a soft-404 (the calibration probes never handshake), and the not-found
	// envelope has no meaning for a body-less upgrade response. Promote it to
	// VHit unconditionally so verify()'s ws-probe promotion path is never
	// silently swallowed by a permissive baseline.
	if r.Status == 101 {
		return VHit, 64
	}
	if !p.Statuses[r.Status] {
		return VHit, 64
	}
	if p.TitleStable && r.Title != "" && !p.Titles[r.Title] {
		return VHit, 64
	}
	best := 64
	for _, s := range p.Sims {
		if d := Hamming(r.Sim, s); d < best {
			best = d
		}
	}
	if best > p.Threshold {
		return VHit, best
	}
	if p.Margin > 0 && best > p.Threshold-p.Margin {
		return VReview, best
	}
	return VNotFound, best
}
