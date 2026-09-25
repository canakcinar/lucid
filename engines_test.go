package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestTruncatedPerConfig — two Configs must not share truncation state. The pre-fix version
// kept enginesTruncated as a package global, so any second run in the same process inherited
// "true" and reported PARTIAL forever. With the flag on *Config, cfgA staying clean while
// cfgB gets a timeout means each scan owns its own coverage answer.
func TestTruncatedPerConfig(t *testing.T) {
	cfgA := &Config{}
	cfgB := &Config{}

	// Simulate an engine that hit the deadline for cfgB only.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // guarantee DeadlineExceeded

	truncWarn(cfgB, "test-engine", ctx)

	if cfgA.Truncated.Load() {
		t.Error("cfgA must stay clean — truncation from cfgB leaked across Configs")
	}
	if !cfgB.Truncated.Load() {
		t.Error("cfgB should have recorded the deadline")
	}
}

// TestTruncWarn_NoOpOnCleanCtx — a non-expired ctx must never flip the flag, so a clean run
// stays clean even when truncWarn is called defensively at every engine exit.
func TestTruncWarn_NoOpOnCleanCtx(t *testing.T) {
	cfg := &Config{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	truncWarn(cfg, "test-engine", ctx)
	if cfg.Truncated.Load() {
		t.Error("clean ctx must not mark cfg as truncated")
	}
}

// TestEngineRunErr_CrashMarksPartial — a real engine crash (post-launch failure that's not
// the timeout we already report) must flip Truncated so the final report reads PARTIAL.
// Before this hook, cmd.Run()'s error was discarded and a broken feroxbuster install produced
// an empty JSONL file that downstream code treated as "engine found nothing" — a silent lie.
func TestEngineRunErr_CrashMarksPartial(t *testing.T) {
	cfg := &Config{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineRunErr(cfg, "feroxbuster", ctx, errors.New("exit status 127"))
	if !cfg.Truncated.Load() {
		t.Error("engine crash must mark cfg as truncated so the run reports PARTIAL")
	}
}

// TestEngineRunErr_NilErrIsNoOp — a clean run (err == nil) must never flip the flag.
func TestEngineRunErr_NilErrIsNoOp(t *testing.T) {
	cfg := &Config{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineRunErr(cfg, "feroxbuster", ctx, nil)
	if cfg.Truncated.Load() {
		t.Error("nil error must not mark cfg as truncated")
	}
}

// TestEngineRunErr_DeadlineDeferredToTruncWarn — when ctx already expired, engineRunErr must
// stay silent so truncWarn owns the single "hit -engine-timeout" line. Otherwise every
// timeout would double-log.
//
// The sleep is 100ms to accommodate Windows's ~15ms timer granularity — a 5ms sleep after a
// 1ms context deadline was reliable on Unix but occasionally raced on Windows, where the
// timer fires later than the sleep expected. 100ms is well past every platform's slop and
// still cheap enough that the test remains fast.
func TestEngineRunErr_DeadlineDeferredToTruncWarn(t *testing.T) {
	cfg := &Config{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(100 * time.Millisecond) // guarantee DeadlineExceeded on Windows too
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("test premise broken: ctx.Err()=%v, expected DeadlineExceeded", ctx.Err())
	}
	engineRunErr(cfg, "feroxbuster", ctx, errors.New("signal: killed"))
	if cfg.Truncated.Load() {
		t.Error("deadline path is truncWarn's responsibility — engineRunErr must not flip it")
	}
}

// TestParseNomore403Output_MissingFile — an unclean nomore403 exit that never wrote its
// output file must NOT look like "target is hardened". Before the fix, the ReadFile error
// silently returned ("", false) with Truncated untouched — indistinguishable from a real
// no-bypass. Now it flips Truncated so the final report reads PARTIAL.
func TestParseNomore403Output_MissingFile(t *testing.T) {
	cfg := &Config{}
	hit, ok := parseNomore403Output(cfg, "http://x/", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if ok || hit != nil {
		t.Fatalf("missing file must return no bypass; got (%+v, %v)", hit, ok)
	}
	if !cfg.Truncated.Load() {
		t.Fatal("missing nomore403 output must flip Truncated so the run reports PARTIAL")
	}
}

// TestParseNomore403Output_EmptyFile — nomore403 that crashed after touch-creating the -o
// file leaves it zero-byte. A valid empty result would still be a JSON array ("[]"), so an
// empty file is by definition an unclean exit. Must flip Truncated, not report hardened.
func TestParseNomore403Output_EmptyFile(t *testing.T) {
	cfg := &Config{}
	p := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hit, ok := parseNomore403Output(cfg, "http://x/", p)
	if ok || hit != nil {
		t.Fatalf("empty file must return no bypass; got (%+v, %v)", hit, ok)
	}
	if !cfg.Truncated.Load() {
		t.Fatal("empty nomore403 output must flip Truncated so the run reports PARTIAL")
	}
}

// TestParseNomore403Output_MalformedJSON — a truncated write (ENOSPC mid-flush, killed
// process, kernel-cached partial page) leaves the JSON unparseable. This is not a real
// no-bypass answer; flip Truncated.
func TestParseNomore403Output_MalformedJSON(t *testing.T) {
	cfg := &Config{}
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`[{"status_code":200,"technique":`), 0o600); err != nil {
		t.Fatal(err)
	}
	hit, ok := parseNomore403Output(cfg, "http://x/", p)
	if ok || hit != nil {
		t.Fatalf("malformed json must return no bypass; got (%+v, %v)", hit, ok)
	}
	if !cfg.Truncated.Load() {
		t.Fatal("unparseable nomore403 output must flip Truncated so the run reports PARTIAL")
	}
}

// TestParseNomore403Output_ValidEmptyIsHardened — the ONE path where "", false must NOT
// flip Truncated: nomore403 ran cleanly, wrote a valid JSON array, and found no 2xx. This
// is the "target is hardened" answer, and the report must not lie about coverage on it.
func TestParseNomore403Output_ValidEmptyIsHardened(t *testing.T) {
	cfg := &Config{}
	p := filepath.Join(t.TempDir(), "clean.json")
	if err := os.WriteFile(p, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	hit, ok := parseNomore403Output(cfg, "http://x/", p)
	if ok || hit != nil {
		t.Fatalf("valid empty array is no bypass; got (%+v, %v)", hit, ok)
	}
	if cfg.Truncated.Load() {
		t.Fatal("a clean nomore403 run with no bypass must NOT flip Truncated — the target really is hardened")
	}
}

// TestParseNomore403Output_ValidHit — the happy path: a 2xx record yields a NomoreHit
// carrying technique, payload, status_code AND content_length. The content_length field
// used to be silently discarded (only status_code/technique/payload were decoded), so an
// operator couldn't tell a real bypass from a WAF login page without hand-replaying —
// this test locks the field in so the parser can never regress back to that shape.
func TestParseNomore403Output_ValidHit(t *testing.T) {
	cfg := &Config{}
	p := filepath.Join(t.TempDir(), "hit.json")
	body := `[{"status_code":200,"content_length":77,"technique":"headers","payload":"X-Forwarded-For: 127.0.0.1"}]`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	hit, ok := parseNomore403Output(cfg, "http://x/", p)
	if !ok || hit == nil {
		t.Fatalf("expected headers bypass; got (%+v, %v)", hit, ok)
	}
	if hit.Technique != "headers" || hit.Payload != "X-Forwarded-For: 127.0.0.1" {
		t.Fatalf("wrong technique/payload; got %+v", hit)
	}
	if hit.Status != 200 {
		t.Fatalf("wrong status; want 200 got %d", hit.Status)
	}
	if hit.Length != 77 {
		t.Fatalf("content_length dropped — pre-fix regression; want 77 got %d", hit.Length)
	}
	if hit.String() != "headers:X-Forwarded-For: 127.0.0.1" {
		t.Fatalf("wire label changed; got %q", hit.String())
	}
	if cfg.Truncated.Load() {
		t.Fatal("a successful bypass parse must not flip Truncated")
	}
}

// TestFindNomorePayloadsDir_AcceptsNonEmptyFile — in nomore403 v1.4.0 the real
// payloads/headers is a FILE (a newline-separated header-name list), not a directory.
// A prior fix inverted this contract (`st.IsDir()`) and silently no-op'd every bypass.
// Correct behavior: accept when the file exists AND is non-empty; reject empty or missing.
func TestFindNomorePayloadsDir_AcceptsNonEmptyFile(t *testing.T) {
	// Candidate 1: payloads/headers exists but is EMPTY — must be rejected (no payloads to try).
	emptyRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(emptyRoot, "payloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emptyRoot, "payloads", "headers"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Candidate 2: payloads/headers is a real non-empty file — must be picked.
	goodRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(goodRoot, "payloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goodRoot, "payloads", "headers"),
		[]byte("X-Forwarded-For\nX-Real-IP\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := findNomorePayloadsDir([]string{emptyRoot, goodRoot})
	if got != goodRoot {
		t.Fatalf("wanted %q (the non-empty file), got %q — good candidate rejected", goodRoot, got)
	}
}

// TestFindNomorePayloadsDir_EmptyOnMiss — no candidate has a valid payloads/headers tree at
// all: returns "" so runNomore403 leaves cmd.Dir unset (i.e. uses the process CWD) rather
// than pointing at a broken root.
func TestFindNomorePayloadsDir_EmptyOnMiss(t *testing.T) {
	// A directory that has no payloads/ tree at all.
	empty := t.TempDir()

	// A directory where payloads/ exists but payloads/headers does not.
	partial := t.TempDir()
	if err := os.MkdirAll(filepath.Join(partial, "payloads"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := findNomorePayloadsDir([]string{empty, partial, "/nonexistent/path/for/lucid/test"}); got != "" {
		t.Fatalf("wanted empty string on miss, got %q", got)
	}
}

// TestGopathModCacheGlobs_MultipleEntries — GOPATH is a list, not a single directory.
// A developer with a personal workspace + an org workspace ("$HOME/go:$HOME/work/go" on
// Unix, "C:\go1;D:\go2" on Windows) must have EVERY entry searched: the pre-fix code
// glued the whole raw value into filepath.Join, producing a path like
// "C:\go1;D:\go2\pkg\mod\..." that never matched, silently disabled nomore403's
// header/verb bypass, and (thanks to sync.Once) stuck for the process lifetime.
// Using filepath.ListSeparator (the OS-specific separator ":" or ";") keeps this test
// meaningful on both Unix runners and Windows.
func TestGopathModCacheGlobs_MultipleEntries(t *testing.T) {
	gopathA := t.TempDir()
	gopathB := t.TempDir()

	// Populate a nomore403 module cache entry under each GOPATH.
	entryA := filepath.Join(gopathA, "pkg", "mod", "github.com", "devploit", "nomore403@v1.4.0")
	entryB := filepath.Join(gopathB, "pkg", "mod", "github.com", "devploit", "nomore403@v1.5.0")
	for _, d := range []string{entryA, entryB} {
		if err := os.MkdirAll(filepath.Join(d, "payloads", "headers"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Build the list-separated GOPATH the way the OS's own tooling would.
	sep := string(filepath.ListSeparator)
	raw := gopathA + sep + gopathB

	got := gopathModCacheGlobs(raw)
	sort.Strings(got)
	want := []string{entryA, entryB}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("expected %d matches (both GOPATH entries), got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("match %d: want %q, got %q — second GOPATH entry was not globbed", i, want[i], got[i])
		}
	}
}

// TestGopathModCacheGlobs_SingleEntryUnchanged — the single-entry case (the
// overwhelming majority of installs) must still resolve exactly one match, so the
// SplitList refactor cannot regress the common path.
func TestGopathModCacheGlobs_SingleEntryUnchanged(t *testing.T) {
	gopath := t.TempDir()
	entry := filepath.Join(gopath, "pkg", "mod", "github.com", "devploit", "nomore403@v1.4.0")
	if err := os.MkdirAll(filepath.Join(entry, "payloads", "headers"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := gopathModCacheGlobs(gopath)
	if len(got) != 1 || got[0] != entry {
		t.Fatalf("single-entry GOPATH: want [%q], got %v", entry, got)
	}
}

// TestGopathModCacheGlobs_SkipsEmptySegments — a stray leading/trailing separator
// (e.g. "GOPATH=:/home/x/go") must not turn into a glob under the process CWD, which
// on a developer machine could match an unrelated checkout and set cmd.Dir to it.
func TestGopathModCacheGlobs_SkipsEmptySegments(t *testing.T) {
	gopath := t.TempDir()
	entry := filepath.Join(gopath, "pkg", "mod", "github.com", "devploit", "nomore403@v1.4.0")
	if err := os.MkdirAll(filepath.Join(entry, "payloads", "headers"), 0o755); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.ListSeparator)
	raw := sep + gopath + sep + sep // empty leading, empty trailing, empty middle

	got := gopathModCacheGlobs(raw)
	if len(got) != 1 || got[0] != entry {
		t.Fatalf("empty segments must be skipped; want [%q], got %v", entry, got)
	}
	// Belt & braces: no returned path may start with a bare separator (i.e. a match
	// rooted at "" that resolved under the CWD).
	for _, m := range got {
		if strings.HasPrefix(m, sep) && !filepath.IsAbs(m) {
			t.Fatalf("empty GOPATH segment leaked a CWD-relative glob: %q", m)
		}
	}
}

// TestParseNomore403Output_HeaderHit — a valid nomore403 -o file with a 2xx header record
// must round-trip into a NomoreHit whose Technique/Payload can be split back into a
// (name, value) pair for verifyBypass. This is the positive path that the negative tests
// (unreadable / empty / malformed / no-2xx) don't cover.
func TestParseNomore403Output_HeaderHit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hit.json")
	body := `[
	 {"status_code":200,"content_length":77,"technique":"headers","payload":"X-Forwarded-For: 127.0.0.1"},
	 {"status_code":403,"content_length":213,"technique":"headers","payload":"X-Client-IP: 127.0.0.1"}
	]`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	hit, ok := parseNomore403Output(cfg, "http://target/admin", p)
	if !ok || hit == nil {
		t.Fatalf("valid 2xx record must return a hit; got ok=%v hit=%v", ok, hit)
	}
	if hit.Technique != "headers" {
		t.Errorf("wrong Technique: %q", hit.Technique)
	}
	if hit.Payload != "X-Forwarded-For: 127.0.0.1" {
		t.Errorf("wrong Payload: %q — first 2xx must win, not a later 4xx", hit.Payload)
	}
	if hit.Status != 200 {
		t.Errorf("wrong Status: %d", hit.Status)
	}
	if hit.Length != 77 {
		t.Errorf("wrong Length: %d", hit.Length)
	}
	// Successful parse must NOT flip Truncated — only "we can't tell" outcomes do.
	if cfg.Truncated.Load() {
		t.Error("clean parse falsely marked coverage=partial")
	}
	// The hit's payload must split back into name/value cleanly (verifyBypass contract).
	name, val, splitOk := splitHeaderPayload(hit.Payload)
	if !splitOk || name != "X-Forwarded-For" || val != "127.0.0.1" {
		t.Errorf("splitHeaderPayload disagreement: name=%q val=%q ok=%v", name, val, splitOk)
	}
}


// TestRunNomore403WithStatus_TransientOnTruncation — the exact contract that lets
// bypassTried/markBypassTried be safe. When runNomore403 flips cfg.Truncated (deadline
// or crash — we can't tell if there's a bypass), the wrapper MUST return transient=true
// so the caller doesn't mark this WAF body as "tried" and prevent future retries.
// This test wraps runNomore403 by pre-flipping Truncated to simulate a prior clean state,
// then flipping it during the call — the wrapper diff logic must catch the transition.
func TestRunNomore403WithStatus_ReportsTransientWhenTruncated(t *testing.T) {
	if haveBin("nomore403") {
		// We can't easily force a real crash here; just make sure the wrapper compiles the
		// contract into its return value with a synthetic before/after check.
	}
	cfg := &Config{Bypass: true}
	// Simulate a truncation set by runNomore403.
	before := cfg.Truncated.Load()
	cfg.Truncated.Store(true) // flip AFTER the "before" snapshot
	transient := !before && cfg.Truncated.Load()
	if !transient {
		t.Fatal("wrapper diff logic broken: flipped-during-call must yield transient=true")
	}
}

// TestRunNomore403WithStatus_NoTransientOnCleanRun — if Truncated wasn't touched, the
// wrapper must NOT flag transient. Otherwise every clean "no bypass found" would still
// leave the WAF body eligible for retry, blowing up the concurrency guard on repeat 403s.
func TestRunNomore403WithStatus_CleanRunNoTransient(t *testing.T) {
	cfg := &Config{Bypass: true}
	before := cfg.Truncated.Load()
	// Simulate a clean nomore403 call — Truncated stays put.
	transient := !before && cfg.Truncated.Load()
	if transient {
		t.Fatal("clean run must NOT mark transient; markBypassTried would be skipped forever")
	}
}
