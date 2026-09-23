package main

// Resume state — the missing 90% of what --resume implied.
//
// The old --resume only read the final findings JSON of a completed prior run and skipped
// verify()ing URLs already listed there. Every other phase re-ran: ferox/ffuf/katana/gau
// hammered the target again (that's most of the wall time), every dir was re-calibrated
// (loud not-found probes), and the root bypass probe was re-issued. And because main.go
// only wrote findings once at the very end, a scan killed mid-run left NO baseline to
// resume from at all.
//
// This file adds three on-disk pieces so -resume/-checkpoint actually pick up mid-scan:
//
//   1. sift.ckpt.jsonl               — one Finding per line, appended under Scanner.mu
//                                      inside record(); a crash preserves everything
//                                      recorded so far. Loaded into skip{} on next run.
//   2. sift.ckpt.jsonl.candidates.json — the candidate union produced by the discovery
//                                      engines. Reused (subject to -resume-ttl) so the
//                                      loud engines don't have to re-run.
//   3. sift.ckpt.jsonl.profiles.json — per-directory calibration Profiles. Reused so
//                                      soft-404 probes don't hit the target again.
//
// The three files together form the two-file contract the user request calls for:
// findings-so-far + candidate cache (with the profile cache as a third convenience file
// so the resumed scan is truly silent on already-mapped dirs).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// candidatesSuffix / profilesSuffix are appended to the checkpoint path to build the sibling
// cache paths. Kept as constants so tests (and any downstream tooling) can name them.
const (
	candidatesSuffix = ".candidates.json"
	profilesSuffix   = ".profiles.json"
)

// candidatesPath / profilesPath are the sibling cache paths derived from a checkpoint path.
func candidatesPath(ckpt string) string {
	if ckpt == "" {
		return ""
	}
	return ckpt + candidatesSuffix
}
func profilesPath(ckpt string) string {
	if ckpt == "" {
		return ""
	}
	return ckpt + profilesSuffix
}

// loadCheckpoint reads a jsonl checkpoint written incrementally by Scanner.record() during a
// prior (possibly crashed) run. Returns the Findings AND the set of URLs already recorded —
// callers hand the URL set to Scanner.skip so those candidates aren't verified again, and
// hand the Findings back to Scanner.SeedFindings so the final report is cumulative rather
// than losing everything the killed run already found.
//
// A missing file is not an error: "no prior checkpoint" is the normal first-run state and
// -checkpoint should still enable append-mode recording. A malformed line IS an error —
// silently truncating half a jsonl gives the operator the impression the scan resumed
// cleanly when it did not.
func loadCheckpoint(path string) ([]Finding, map[string]bool, error) {
	set := map[string]bool{}
	if path == "" {
		return nil, set, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, set, nil
		}
		return nil, set, err
	}
	defer f.Close()
	var findings []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var fnd Finding
		if err := json.Unmarshal(raw, &fnd); err != nil {
			return findings, set, fmt.Errorf("checkpoint %s: line %d: %w", path, line, err)
		}
		findings = append(findings, fnd)
		if fnd.URL != "" {
			set[fnd.URL] = true
		}
		// A collapsed row stands for many URLs (e.g. a uniform-wall aggregate). Every Member
		// is effectively already accounted for — don't re-verify any of them on resume.
		for _, m := range fnd.Members {
			set[m] = true
		}
	}
	if err := sc.Err(); err != nil {
		return findings, set, err
	}
	return findings, set, nil
}

// candidateCache is the on-disk shape of <checkpoint>.candidates.json — the discovery-phase
// output pinned to a target and a wall-clock timestamp. Target-scoping means pointing sift
// at a different host with the same -checkpoint doesn't silently reuse the wrong union.
type candidateCache struct {
	Target string          `json:"target"`
	At     int64           `json:"at"` // unix seconds
	Union  []candCacheItem `json:"union"`
}

// candCacheItem is the JSON-serializable projection of the internal cand{}. The scanner's
// cand type has unexported fields — encoding/json can't touch those, so mirror them here.
type candCacheItem struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Status int    `json:"status"`
}

// loadCandidates returns (union, true, nil) when a fresh cache for the same target exists,
// (nil, false, nil) for a cache miss (missing file / different target / expired), and
// (nil, false, err) when the file is present but unreadable/malformed. A malformed cache is
// treated as an error rather than silently rerunning discovery: the operator asked to
// resume, and an unreadable state file is a bug they should see.
func loadCandidates(path, target string, ttl int, force bool) (map[string]cand, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var c candidateCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, false, fmt.Errorf("candidate cache %s: %w", path, err)
	}
	if c.Target != target {
		// Different target — the union is not portable across hosts. Not an error, just a miss.
		return nil, false, nil
	}
	if !force && ttl > 0 && time.Now().Unix()-c.At > int64(ttl) {
		return nil, false, nil
	}
	m := make(map[string]cand, len(c.Union))
	for _, cc := range c.Union {
		if cc.URL == "" {
			continue
		}
		m[cc.URL] = cand{url: cc.URL, source: cc.Source, status: cc.Status}
	}
	return m, true, nil
}

// saveCandidates writes the discovery union to the sibling cache file. Sorted keys so the
// file diffs cleanly across runs, which matters when this cache is committed to a job repo.
func saveCandidates(path, target string, union map[string]cand) error {
	if path == "" {
		return nil
	}
	c := candidateCache{Target: target, At: time.Now().Unix()}
	c.Union = make([]candCacheItem, 0, len(union))
	for _, v := range union {
		c.Union = append(c.Union, candCacheItem{URL: v.url, Source: v.source, Status: v.status})
	}
	sort.Slice(c.Union, func(i, j int) bool { return c.Union[i].URL < c.Union[j].URL })
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// profileCache is the on-disk shape of <checkpoint>.profiles.json — the per-directory
// not-found calibrations. Persisting these means a resumed scan doesn't have to re-issue
// the calibration probes (which HIT the target — arguably the loudest per-dir traffic).
type profileCache struct {
	Target   string             `json:"target"`
	At       int64              `json:"at"`
	Profiles map[string]Profile `json:"profiles"`
}

// loadProfiles mirrors loadCandidates: fresh cache -> map, stale/missing/other-target -> nil,
// unreadable/malformed -> error. Nil map means "no cached profiles, calibrate normally".
func loadProfiles(path, target string, ttl int, force bool) (map[string]Profile, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c profileCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("profile cache %s: %w", path, err)
	}
	if c.Target != target {
		return nil, nil
	}
	if !force && ttl > 0 && time.Now().Unix()-c.At > int64(ttl) {
		return nil, nil
	}
	return c.Profiles, nil
}

// saveProfiles writes the calibration map. Empty map is a no-op so an early-aborted scan
// (target unreachable) doesn't overwrite a previously good cache with an empty one.
func saveProfiles(path, target string, m map[string]Profile) error {
	if path == "" || len(m) == 0 {
		return nil
	}
	c := profileCache{Target: target, At: time.Now().Unix(), Profiles: m}
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
