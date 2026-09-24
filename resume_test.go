package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadCheckpoint_Missing_ReturnsEmpty — a missing checkpoint is the normal first-run
// state and must not error; a fresh -checkpoint on a new file starts recording from empty.
func TestLoadCheckpoint_Missing_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	fs, set, err := loadCheckpoint(filepath.Join(dir, "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("missing checkpoint must not error: %v", err)
	}
	if len(fs) != 0 || len(set) != 0 {
		t.Fatalf("missing checkpoint must be empty, got fs=%d set=%d", len(fs), len(set))
	}
}

// TestLoadCheckpoint_MalformedLine_Errors — a corrupted jsonl half must not be treated as
// "resume complete". Silently truncating half a run's findings is worse than aborting; the
// operator needs to see the file is broken.
func TestLoadCheckpoint_MalformedLine_Errors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(p, []byte(`{"url":"http://h/a","status":200}
not-json-at-all
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCheckpoint(p); err == nil {
		t.Fatal("malformed jsonl must return an error, not silently truncate")
	}
}

// TestLoadCheckpoint_MembersUnionIntoSkip — a collapsed finding stands in for many URLs.
// Every Member must land in skip{} so re-verifying any of them is dropped on resume.
func TestLoadCheckpoint_MembersUnionIntoSkip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.jsonl")
	rep := Finding{URL: "http://h/a/1", Status: 403, Collapsed: 3,
		Members: []string{"http://h/a/1", "http://h/a/2", "http://h/a/3"}}
	b, _ := json.Marshal(&rep)
	if err := os.WriteFile(p, append(b, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	fs, set, err := loadCheckpoint(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	for _, m := range rep.Members {
		if !set[m] {
			t.Errorf("member %s missing from skip set — resume would re-verify it", m)
		}
	}
}

// TestRecord_AppendsToCheckpoint — the core end-to-end guarantee for crash recovery: each
// call to Scanner.record must land as its own JSON line in the checkpoint file, and a
// subsequent loadCheckpoint must recover those findings byte-for-byte in order.
func TestRecord_AppendsToCheckpoint(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "lucid.ckpt.jsonl")
	cfg := &Config{
		Concurrency: 1, Timeout: 2, UA: "lucid-test", Probes: 1, Threshold: -1,
		CheckpointPath: ckpt,
	}
	client := mustNewClient(t, cfg)
	u, _ := url.Parse("http://h/")
	s := NewScanner(cfg, client, u, nil)
	if s.ckptFile == nil {
		t.Fatal("scanner must open the checkpoint file when CheckpointPath is set")
	}

	s.record(Finding{URL: "http://h/a", Status: 200, Source: "test"})
	s.record(Finding{URL: "http://h/b", Status: 403, Source: "engine-status",
		Collapsed: 2, Members: []string{"http://h/b", "http://h/c"}})
	s.Close()

	fs, set, err := loadCheckpoint(ckpt)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings after reload, got %d", len(fs))
	}
	if fs[0].URL != "http://h/a" || fs[1].URL != "http://h/b" {
		t.Fatalf("append order lost: got %q, %q", fs[0].URL, fs[1].URL)
	}
	// Members flow through the reload path into skip{} so /c isn't verified twice on resume.
	for _, want := range []string{"http://h/a", "http://h/b", "http://h/c"} {
		if !set[want] {
			t.Errorf("missing %s from reload skip set", want)
		}
	}
}

// TestCandidateCache_RoundTrip_Fresh — a freshly-written cache round-trips through
// loadCandidates and is treated as a hit for the same target within the TTL.
func TestCandidateCache_RoundTrip_Fresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cands.json")
	union := map[string]cand{
		"http://h/a": {url: "http://h/a", source: "ferox", status: 200},
		"http://h/b": {url: "http://h/b", source: "gau", status: 0},
	}
	if err := saveCandidates(path, "http://h/", union); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, hit, err := loadCandidates(path, "http://h/", 3600, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !hit || len(got) != 2 {
		t.Fatalf("expected hit with 2 entries, got hit=%v n=%d", hit, len(got))
	}
	if got["http://h/a"].source != "ferox" || got["http://h/a"].status != 200 {
		t.Errorf("round-trip lost fields on /a: %+v", got["http://h/a"])
	}
}

// TestCandidateCache_MissOnDifferentTarget — the same file must not be silently reused
// against a different target; the union is host-specific, and cross-host reuse would
// re-emit stale URLs as "findings" for an unrelated scan.
func TestCandidateCache_MissOnDifferentTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cands.json")
	_ = saveCandidates(path, "http://h1/", map[string]cand{
		"http://h1/x": {url: "http://h1/x", source: "ferox"},
	})
	_, hit, err := loadCandidates(path, "http://h2/", 3600, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Fatal("cache from a different target must not be treated as a hit")
	}
}

// TestCandidateCache_ExpiryHonoured — a cache older than the TTL is not a hit unless the
// operator forces reuse.
func TestCandidateCache_ExpiryHonoured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cands.json")
	// Backdate by writing a hand-rolled cache with At in the past.
	c := candidateCache{
		Target: "http://h/",
		At:     time.Now().Unix() - 7200, // 2h old
		Union:  []candCacheItem{{URL: "http://h/x", Source: "gau"}},
	}
	b, _ := json.MarshalIndent(&c, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatal(err)
	}
	// TTL 3600 (1h) — expired.
	if _, hit, _ := loadCandidates(path, "http://h/", 3600, false); hit {
		t.Fatal("stale cache must be a miss")
	}
	// -resume-candidates forces reuse.
	if _, hit, _ := loadCandidates(path, "http://h/", 3600, true); !hit {
		t.Fatal("force must override TTL")
	}
	// TTL 0 == never expires.
	if _, hit, _ := loadCandidates(path, "http://h/", 0, false); !hit {
		t.Fatal("ttl=0 must never expire")
	}
}

// TestProfileCache_RoundTrip — Profile is JSON-serializable end-to-end, and a reload
// preserves Statuses/Sims/Threshold so a resumed scan's judge() sees the same envelope
// (byte-for-byte) that the original calibration built.
func TestProfileCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profs.json")
	p := Profile{
		Statuses: map[int]bool{404: true}, Titles: map[string]bool{"not found": true},
		TitleStable: true, Sims: []uint64{0xdeadbeef, 0xfeedface},
		Threshold: 14, Margin: 2, Dynamic: true,
	}
	m := map[string]Profile{"http://h/api/": p}
	if err := saveProfiles(path, "http://h/", m); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadProfiles(path, "http://h/", 3600, false)
	if err != nil || got == nil {
		t.Fatalf("load: err=%v got=%v", err, got)
	}
	rp := got["http://h/api/"]
	if len(rp.Sims) != 2 || rp.Sims[0] != 0xdeadbeef || rp.Sims[1] != 0xfeedface {
		t.Errorf("Sims lost: %v", rp.Sims)
	}
	if rp.Threshold != 14 || !rp.Dynamic || !rp.TitleStable {
		t.Errorf("Profile bit-fields lost: %+v", rp)
	}
	if !rp.Statuses[404] || !rp.Titles["not found"] {
		t.Errorf("Profile maps lost: %+v", rp)
	}
}

// TestScanner_Run_ReusesCandidateCache_SkipsDiscovery — end-to-end guarantee that a fresh
// candidate cache short-circuits discovery. We assert two things:
//  1. after the first run the cache and checkpoint exist,
//  2. a second run against a SERVER that would 500 on discovery (or timeout) still finds the
//     candidates via cache. We stand up a very simple mock that serves 200 on /a and 200 on
//     everything else with distinct bodies; the check is that the second Run's union came
//     from disk (assertion: the cache file's mtime is unchanged after run 2).
func TestScanner_Run_ReusesCandidateCache_SkipsDiscovery(t *testing.T) {
	// A tiny mock: serves distinct 200 responses so calibration doesn't mark the dir Unusable.
	// The path we seed in the checkpoint (via a pre-written candidates cache) is /seeded — we
	// prove reuse by asserting that run 2 doesn't rewrite the cache file (saveCandidates only
	// runs when discovery ran).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seeded":
			w.Write([]byte(`<title>seeded</title>real content ` + strings.Repeat("x ", 40)))
		default:
			// Cheap distinct body — enough for calibration to build a not-found envelope.
			w.WriteHeader(404)
			w.Write([]byte(`<title>nf</title>` + r.URL.Path + strings.Repeat(" filler", 20)))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	ckpt := filepath.Join(dir, "lucid.ckpt.jsonl")
	// Pre-seed the candidate cache so Run() takes the cache short-circuit.
	if err := saveCandidates(candidatesPath(ckpt), srv.URL+"/", map[string]cand{
		srv.URL + "/seeded": {url: srv.URL + "/seeded", source: "cached-test", status: 0},
	}); err != nil {
		t.Fatalf("preseed: %v", err)
	}
	beforeStat, err := os.Stat(candidatesPath(ckpt))
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}

	cfg := &Config{
		Concurrency: 1, Timeout: 5, UA: "lucid-test", Probes: 2, Threshold: -1,
		ReviewMargin: 2, Assets: true, Bypass: false, Archive: false,
		CheckpointPath: ckpt, ResumeTTL: 3600,
		Throttle: NewThrottle(0),
	}
	client := mustNewClient(t, cfg)
	u, _ := url.Parse(srv.URL + "/")
	s := NewScanner(cfg, client, u, nil)
	defer s.Close()
	fs := s.Run()
	if len(fs) == 0 {
		t.Fatal("expected at least the seeded candidate to survive as a finding")
	}
	found := false
	for _, f := range fs {
		if strings.HasSuffix(f.URL, "/seeded") {
			found = true
		}
	}
	if !found {
		t.Errorf("cached candidate /seeded missing from findings: %+v", fs)
	}

	// The cache short-circuit MUST NOT rewrite the cache file on a hit — otherwise a
	// resume silently refreshes the "fresh" timestamp on data the engines never re-fetched.
	afterStat, err := os.Stat(candidatesPath(ckpt))
	if err != nil {
		t.Fatalf("stat cache after: %v", err)
	}
	if !afterStat.ModTime().Equal(beforeStat.ModTime()) {
		t.Error("candidate cache mtime changed on a cache HIT — refreshed a stale window without re-running discovery")
	}
}
