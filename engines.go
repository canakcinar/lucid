package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"strconv"
	"strings"
	"time"
)

// Truncation is now per-Config (see Config.Truncated) so state can't bleed across scans.

// nomore403 configuration lives in one place so nomoreBudget's timeout formula stays in sync
// with the actual command line. Change these and the deadline auto-adjusts; drift silently was
// the pre-fix bug ("techniques := 4" was baked into the formula but the -k list said 4 techs).
const (
	nomore403Techniques      = "headers,verbs,endpaths,path-case"
	nomore403PayloadsPerTech = 80 // avg entries in default nomore403 payload files
	nomore403ReqTimeoutMs    = 2000
	nomore403Concurrency     = 30
)

// nomoreBudget derives a work-appropriate deadline for nomore403: 4 techniques × ~80 payloads
// × per-request timeout / concurrency, with 1.5× hedge and a 30s minimum. Prevents a keyword
// like "90s" appearing anywhere — every timeout is derived from what the tool actually does.
func nomoreBudget(cfg *Config) int {
	// These constants MUST track the -k technique list, -m concurrency, and --timeout below.
	// When we change nomoreArgs, we change these — otherwise the derived deadline silently
	// drifts and a wide technique list is killed before it can find a real bypass.
	techniques := len(strings.Split(nomore403Techniques, ","))
	payloads := nomore403PayloadsPerTech
	reqSec := nomore403ReqTimeoutMs / 1000
	if reqSec < 1 {
		reqSec = 1
	}
	concurrency := nomore403Concurrency
	seconds := techniques * payloads * reqSec / concurrency
	seconds = seconds * 3 / 2 // 1.5× hedge for network jitter
	if seconds < 30 {
		seconds = 30
	}
	if cfg.Rate > 0 {
		// If the user throttled us, the wall time grows — add the throttled floor.
		floor := techniques * payloads / cfg.Rate
		if floor > seconds {
			seconds = floor + 15
		}
	}
	return seconds
}

// nomorePayloadsDir finds a directory that contains nomore403's ./payloads/headers subtree —
// either bundled next to the binary or in the Go module cache. Cached after first lookup.
var (
	nmDirOnce sync.Once
	nmDir     string
)

func nomorePayloadsDir() string {
	nmDirOnce.Do(func() {
		cands := []string{}
		if bin, err := exec.LookPath("nomore403"); err == nil {
			cands = append(cands, filepath.Dir(bin))
		}
		if gp := os.Getenv("GOPATH"); gp != "" {
			cands = append(cands, gopathModCacheGlobs(gp)...)
		}
		if home, err := os.UserHomeDir(); err == nil {
			matches, _ := filepath.Glob(filepath.Join(home, "go/pkg/mod/github.com/devploit/nomore403@*"))
			cands = append(cands, matches...)
		}
		nmDir = findNomorePayloadsDir(cands)
	})
	return nmDir
}

// gopathModCacheGlobs expands every entry in a raw GOPATH value into candidate roots
// where the nomore403 module may be extracted. GOPATH is officially a list separated by
// filepath.ListSeparator — ":" on Unix, ";" on Windows — so we must split with
// filepath.SplitList before globbing: treating the whole thing as one directory turned
// a common developer setup ("$HOME/go:$HOME/work/go" on Unix, "C:\go1;D:\go2" on
// Windows) into a nonsense path that never matched, silently disabled the header/verb
// bypass techniques, and (thanks to sync.Once) stuck for the rest of the process.
// Empty entries — e.g. a leading or trailing separator, or an unset segment — are
// skipped so we don't glob under the process CWD by accident.
func gopathModCacheGlobs(gp string) []string {
	var out []string
	for _, entry := range filepath.SplitList(gp) {
		if entry == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(entry, "pkg/mod/github.com/devploit/nomore403@*"))
		out = append(out, matches...)
	}
	return out
}

// findNomorePayloadsDir picks the first candidate whose payloads/headers subtree is a real
// directory. Split out from nomorePayloadsDir so tests can exercise the "stray file at
// payloads/headers" and "empty candidates" cases without poisoning the sync.Once cache.
// Guarding on IsDir is load-bearing: a zero-byte file, dangling symlink, or half-extracted
// module cache entry at that path used to be accepted as a valid root, which then set
// cmd.Dir to a directory where nomore403's headers/verbs techniques silently no-op.
func findNomorePayloadsDir(cands []string) string {
	// nomore403's payloads/headers is a file (list of header names to try), not a directory —
	// requiring IsDir() here silently broke the XFF bypass discovery. We just need the payload
	// list to exist and be non-empty.
	for _, d := range cands {
		st, err := os.Stat(filepath.Join(d, "payloads", "headers"))
		if err == nil && !st.IsDir() && st.Size() > 0 {
			return d
		}
	}
	return ""
}

// sift orchestrates mature discovery/bypass tools when they're installed and cleans their union
// with its own SimHash core. Every wrapper degrades gracefully (missing binary -> nil) and every
// external process is bounded so it can't hang the run.

func haveBin(b string) bool { _, err := exec.LookPath(b); return err == nil }

// engineCmd bounds every external tool by cfg.EngineTimeout so none can hang the scan.
// Parent is rootCtx so a SIGINT/SIGTERM handled by installSignalHandler cascades into
// every engine's context and tears the child down via killGroup (below) — otherwise a
// non-interactive run leaves feroxbuster/katana/gau/nomore403 orphaned.
func engineCmd(cfg *Config, name string, args ...string) (*exec.Cmd, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(rootCtx, time.Duration(cfg.EngineTimeout)*time.Second)
	cmd := exec.CommandContext(ctx, name, args...)
	setPgid(cmd)
	// Override the default Kill-the-direct-child cancel with a group signal so
	// grandchildren (engine workers) go with the parent.
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = 3 * time.Second
	return cmd, ctx, cancel
}

// truncWarn shouts when an engine was killed by the timeout mid-run — its output is PARTIAL, so a
// real path (alphabetically late in the wordlist, etc.) may have been silently missed.
func truncWarn(cfg *Config, name string, ctx context.Context) {
	if ctx.Err() == context.DeadlineExceeded {
		cfg.Truncated.Store(true)
		fmt.Fprintf(os.Stderr, "\x1b[33m[!] %s hit -engine-timeout — results are PARTIAL; raise -engine-timeout or lower coverage/rate\x1b[0m\n", name)
	}
}

// engineRunErr surfaces a real engine crash (missing shared library, OOM kill, permission
// denied on the temp file, ENOSPC on the JSONL output, or any other post-launch failure)
// that truncWarn's deadline check silently swallows. Before this hook, cmd.Run()'s error
// return was discarded — a broken install produced an empty output file and looked exactly
// like "engine ran fine and found nothing". Now the scan flips to PARTIAL and stderr names
// the failing engine, so operators know their result set is short.
func engineRunErr(cfg *Config, name string, ctx context.Context, err error) {
	if err == nil {
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		return // truncWarn already reported this — don't double-log.
	}
	cfg.Truncated.Store(true)
	fmt.Fprintf(os.Stderr, "\x1b[33m[!] engine %s failed: %v — results are PARTIAL\x1b[0m\n", name, err)
}

func trimDots(exts []string) []string {
	out := make([]string, 0, len(exts))
	for _, e := range exts {
		out = append(out, strings.TrimPrefix(e, "."))
	}
	return out
}

func runLines(cmd *exec.Cmd) ([]string, error) {
	out, err := cmd.Output() // non-zero exit still yields partial output; err surfaces the failure
	var res []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, "http") {
			res = append(res, l)
		}
	}
	return res, err
}

// feroxbuster: fast recursive brute engine. --json gives url+status per hit, so sift can skip
// re-fetching a uniform 403/401 wall (the status already tells it those are the wall).
func runFerox(targetURL, wordlist string, cfg *Config) map[string]int {
	if wordlist == "" || !haveBin("feroxbuster") {
		return nil
	}
	tmp, err := createTracked("", "sift-ferox-*.jsonl")
	if err != nil {
		return nil
	}
	tmp.Close()
	defer func() { os.Remove(tmp.Name()); unregisterTemp(tmp.Name()) }()
	a := []string{"-u", targetURL, "-w", wordlist, "--json", "-o", tmp.Name(), "--silent", "-k",
		"-d", strconv.Itoa(cfg.MaxDepth + 1), "-t", strconv.Itoa(cfg.Concurrency)}
	if len(cfg.Exts) > 0 {
		a = append(a, "-x", strings.Join(trimDots(cfg.Exts), ","))
	}
	if cfg.Rate > 0 { // throttle the loud brute engine too, not just sift's own fetches
		a = append(a, "--rate-limit", strconv.Itoa(cfg.Rate))
	}
	if cfg.Proxy != "" {
		a = append(a, "-p", cfg.Proxy)
	}
	cmd, ctx, cancel := engineCmd(cfg, "feroxbuster", a...)
	defer cancel()
	err = cmd.Run()
	truncWarn(cfg, "feroxbuster", ctx)
	engineRunErr(cfg, "feroxbuster", ctx, err)
	f, err := os.Open(tmp.Name())
	if err != nil {
		return nil
	}
	defer f.Close()
	res := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var o struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		if json.Unmarshal(sc.Bytes(), &o) == nil && o.Type == "response" && o.URL != "" {
			res[o.URL] = o.Status
		}
	}
	return res
}

// ffuf fallback brute engine (JSON out -> url+status).
func runFfuf(targetURL, wordlist string, cfg *Config) map[string]int {
	if wordlist == "" || !haveBin("ffuf") {
		return nil
	}
	tmp, err := createTracked("", "sift-ffuf-*.json")
	if err != nil {
		return nil
	}
	tmp.Close()
	defer func() { os.Remove(tmp.Name()); unregisterTemp(tmp.Name()) }()
	u := strings.TrimSuffix(targetURL, "/") + "/FUZZ"
	a := []string{"-w", wordlist, "-u", u, "-mc", "200,204,301,302,307,401,403,405",
		"-ac", "-t", strconv.Itoa(cfg.Concurrency), "-of", "json", "-o", tmp.Name(), "-s"}
	if cfg.Rate > 0 {
		a = append(a, "-rate", strconv.Itoa(cfg.Rate))
	}
	if cfg.Proxy != "" {
		a = append(a, "-x", cfg.Proxy)
	}
	cmd, ctx, cancel := engineCmd(cfg, "ffuf", a...)
	defer cancel()
	err = cmd.Run()
	truncWarn(cfg, "ffuf", ctx)
	engineRunErr(cfg, "ffuf", ctx, err)
	b, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil
	}
	var parsed struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		} `json:"results"`
	}
	if json.Unmarshal(b, &parsed) != nil {
		return nil
	}
	res := map[string]int{}
	for _, r := range parsed.Results {
		res[r.URL] = r.Status
	}
	return res
}

// katana: crawl + JavaScript endpoint extraction (-jc) + known files robots/sitemap (-kf all).
func runKatana(targetURL string, cfg *Config) []string {
	if !haveBin("katana") {
		return nil
	}
	d := cfg.MaxDepth + 1
	if d < 3 {
		d = 3 // -kf all needs depth >= 3
	}
	a := []string{"-u", targetURL, "-jc", "-kf", "all", "-silent", "-d", strconv.Itoa(d)}
	if cfg.Rate > 0 {
		a = append(a, "-rl", strconv.Itoa(cfg.Rate))
	}
	if cfg.Proxy != "" {
		a = append(a, "-proxy", cfg.Proxy)
	}
	cmd, ctx, cancel := engineCmd(cfg, "katana", a...)
	defer cancel()
	out, err := runLines(cmd)
	truncWarn(cfg, "katana", ctx)
	engineRunErr(cfg, "katana", ctx, err)
	return out
}

// gau: historical URLs from public archives (Wayback, CommonCrawl, …). Zero requests to target.
func runGau(host string, cfg *Config) []string {
	if !cfg.Archive || !haveBin("gau") {
		return nil
	}
	cmd, ctx, cancel := engineCmd(cfg, "gau", "--threads", "5", host)
	defer cancel()
	urls, err := runLines(cmd)
	truncWarn(cfg, "gau", ctx)
	engineRunErr(cfg, "gau", ctx, err)
	if cfg.MaxCandidates > 0 && len(urls) > cfg.MaxCandidates {
		urls = urls[:cfg.MaxCandidates] // gau can return 100k+; cap the explosion at the source
	}
	return urls
}

// NomoreHit is the parsed 2xx record from nomore403's -o JSON: enough for the caller to both
// label the finding (Technique[+Payload]) AND replay the winning request in-process for the
// header technique (nomore403 speaks a simple "Name: Value" payload there). Length carries
// the content_length nomore403 already computed — used as a hint when we can't replay
// (verb-tunneling with non-standard verbs) so the operator at least sees "hit was 8.4 KB
// vs the wall's 213 B" instead of just a bare technique string.
type NomoreHit struct {
	Technique string // "headers", "verbs", "endpaths", "path-case"
	Payload   string // technique-specific — for headers, "Header-Name: value"
	Status    int    // 2xx that made nomore403 flag this record
	Length    int    // content_length from the nomore403 record (bytes)
}

// String renders technique[:payload], matching the wire format callers used before
// runNomore403 returned a struct.
func (h *NomoreHit) String() string {
	if h == nil {
		return ""
	}
	if h.Payload != "" {
		return h.Technique + ":" + h.Payload
	}
	return h.Technique
}

// runNomore403 delegates 403/401 bypass to nomore403. Timeout is derived from the workload
// (payload count × per-request time × margin) so a real bypass is never silently cut off,
// while a broken/hung nomore403 still can't stall the scan (hard cap at EngineTimeout).
// A deadline hit sets enginesTruncated so the final "coverage: PARTIAL" tells the reader.
// runNomore403WithStatus wraps runNomore403 and reports whether the run terminated cleanly.
// transient=true means we can't tell if there's a bypass — timeout, crash, or unparseable JSON.
// Callers use this to decide whether marking the sim as "tried" is safe: a transient failure must
// NOT permanently disable retries for the same WAF body on subsequent 403s.
func runNomore403WithStatus(rawurl string, cfg *Config) (hit *NomoreHit, ok bool, transient bool) {
	before := cfg.Truncated.Load()
	hit, ok = runNomore403(rawurl, cfg)
	// runNomore403 flips cfg.Truncated on deadline (context.DeadlineExceeded) or engine crash
	// (engineRunErr). Either way it means "we didn't get a clean answer" — retry-safe.
	if !before && cfg.Truncated.Load() {
		transient = true
	}
	return
}

func runNomore403(rawurl string, cfg *Config) (*NomoreHit, bool) {
	if !cfg.Bypass || !haveBin("nomore403") {
		return nil, false
	}
	tmp, err := createTracked("", "sift-nm-*.json")
	if err != nil {
		return nil, false
	}
	tmp.Close()
	defer func() { os.Remove(tmp.Name()); unregisterTemp(tmp.Name()) }()
	// Deadline: work-derived, not guessed. ~4 techniques × ~80 payloads × ~1s each = ~320s in
	// the worst case; give it half that as a hedge, then cap at the user-configured hang net.
	need := nomoreBudget(cfg)
	if need > cfg.EngineTimeout {
		need = cfg.EngineTimeout
	}
	// Parent is rootCtx (see engineCmd) so a SIGINT/SIGTERM aborts nomore403 along
	// with the rest of the scan instead of leaking the child.
	ctx, cancel := context.WithTimeout(rootCtx, time.Duration(need)*time.Second)
	defer cancel()
	// Removed "--status 200": it silently produced empty JSON in v1.4.0 even when a 200 existed.
	// We filter for 2xx ourselves after parsing. Real schema is
	// {"status_code":200,"content_length":77,"technique":"headers","payload":"X-Forwarded-For: 127.0.0.1"}.
	// Also dropped "-d" (per-request delay): -m already caps concurrency; adding delay stacks with
	// the goroutine limit and blew the timeout without helping the target.
	a := []string{"-u", rawurl, "-k", nomore403Techniques,
		"--timeout", strconv.Itoa(nomore403ReqTimeoutMs),
		"-m", strconv.Itoa(nomore403Concurrency),
		"--no-banner", "--json", "-o", tmp.Name()}
	cmd := exec.CommandContext(ctx, "nomore403", a...)
	setPgid(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = 3 * time.Second
	// nomore403 loads payloads from ./payloads/ relative to CWD; without Cmd.Dir its header/verb
	// techniques silently skip ("Skipping headers technique: no such file"), turning bypass into
	// a no-op. Point at the installed module's copy.
	if pd := nomorePayloadsDir(); pd != "" {
		cmd.Dir = pd
	}
	runErr := cmd.Run()
	// If we hit the deadline, surface it — the same way engine truncation does. Otherwise a
	// missing bypass looks like "target is hardened" when it may just mean "we ran out of time".
	if ctx.Err() == context.DeadlineExceeded {
		cfg.Truncated.Store(true)
		fmt.Fprintf(os.Stderr, "\x1b[33m[!] nomore403 hit deadline (%ds) on %s — bypass check PARTIAL\x1b[0m\n", need, rawurl)
	} else {
		// A crash (missing shared lib, OOM, ENOSPC on the JSONL) after haveBin() otherwise
		// looks identical to "no bypass found" — flag it so the run reports PARTIAL.
		engineRunErr(cfg, "nomore403", ctx, runErr)
	}
	return parseNomore403Output(cfg, rawurl, tmp.Name())
}

// parseNomore403Output reads nomore403's -o JSON file and picks the first 2xx bypass.
// Split out from runNomore403 so the four "we can't tell" branches (unreadable file,
// empty file, unparseable JSON, no 2xx record) can be exercised directly by tests.
// Distinguishes "target is hardened" (valid empty/no-2xx JSON — return nil, false with
// Truncated untouched) from "we can't tell" (unclean exit that left the file broken —
// flip Truncated, log to stderr, still return nil, false). Without this split the four
// silent-failure paths collapsed into the same tuple as a real "no bypass".
//
// The returned *NomoreHit carries content_length as well as status_code/technique/payload
// so the caller can verify a header-technique hit in-process (replay + Profile.isNotFound)
// and, for techniques we can't replay, at least surface the response size so an operator
// can distinguish a 200 "login page" false-positive from a real bypass without hand-replaying.
func parseNomore403Output(cfg *Config, rawurl, path string) (*NomoreHit, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		cfg.Truncated.Store(true)
		fmt.Fprintf(os.Stderr, "\x1b[33m[!] nomore403 output unreadable on %s: %v — bypass check PARTIAL\x1b[0m\n", rawurl, err)
		return nil, false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		cfg.Truncated.Store(true)
		fmt.Fprintf(os.Stderr, "\x1b[33m[!] nomore403 output empty on %s — bypass check PARTIAL\x1b[0m\n", rawurl)
		return nil, false
	}
	var recs []struct {
		StatusCode    int    `json:"status_code"`
		ContentLength int    `json:"content_length"`
		Technique     string `json:"technique"`
		Payload       string `json:"payload"`
	}
	if err := json.Unmarshal(b, &recs); err != nil {
		cfg.Truncated.Store(true)
		fmt.Fprintf(os.Stderr, "\x1b[33m[!] nomore403 output unparseable on %s: %v — bypass check PARTIAL\x1b[0m\n", rawurl, err)
		return nil, false
	}
	for _, r := range recs {
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			return &NomoreHit{
				Technique: r.Technique,
				Payload:   r.Payload,
				Status:    r.StatusCode,
				Length:    r.ContentLength,
			}, true
		}
	}
	return nil, false
}
