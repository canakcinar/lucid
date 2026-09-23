package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type cand struct {
	url, source string
	status      int // status reported by the engine (0 = unknown, e.g. katana/gau)
}

// Scanner is the orchestration brain: external tools discover, sift's SimHash core cleans their
// union per directory, and nomore403 handles 403s. Nothing here re-implements a tool's job.
type Scanner struct {
	cfg    *Config
	client *http.Client
	target *url.URL

	baseSim uint64 // homepage/shell signature, for catch-all/SPA detection & shell tagging
	skip    map[string]bool

	mu       sync.Mutex
	findings []Finding
	tried403 []uint64      // SimHashes of 403/401 pages already sent to nomore403
	nmSem    chan struct{} // caps concurrent nomore403 processes

	// Fetch health counters — a total-network-failure mid-scan (DNS blip, WAF-level TCP RST,
	// TLS handshake regression) would otherwise silently drop every candidate and leave the
	// operator with a "0 findings, coverage: complete" report indistinguishable from a clean
	// target. Track attempted verify()-fetches and how many returned r.Err; at end-of-run,
	// if the error rate crosses the threshold, flip cfg.Truncated so coverage reads PARTIAL.
	// OffScope is NOT counted — off-host redirects are expected and don't imply blindness.
	attempts  atomic.Int64
	fetchErrs atomic.Int64

	// ckptFile is the append-mode jsonl handle written under s.mu inside record(). Non-nil
	// only when cfg.CheckpointPath is set. Each recorded Finding survives a mid-run crash
	// and is loaded into skip{} on the next -checkpoint run.
	ckptFile *os.File

	// HAR capture buffer. Non-nil only when cfg.HAROutput != "" — scans without -har allocate
	// nothing here. Populated by verify() alongside record(), serialized in main() at scan end.
	har *harScope
}

// fetchErrThreshold is the fraction of attempted verify-fetches that may fail before we
// call the scan blind. 20% picks up systemic breakage (WAF flipped on, upstream down)
// while tolerating incidental timeouts on a long tail.
// fetchErrThreshold lives in constants.go.

// bypassTried returns true if a near-identical 403/401 body was already handed to nomore403 —
// so a WAF that returns one block page for 57 paths triggers a single bypass attempt, not 57.
// Membership check only — the caller records the sim as tried via markBypassTried AFTER nomore403
// actually completed. This lets a transient failure (network hiccup, nomore403 crash) be retried
// on the next 401/403 with the same body instead of being permanently disabled.
func (s *Scanner) bypassTried(sim uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tried403 {
		if Hamming(t, sim) <= 2 {
			return true
		}
	}
	return false
}

// markBypassTried records that a bypass check finished for this body signature — only
// success or a definitive negative should reach here, never a transient error.
func (s *Scanner) markBypassTried(sim uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recheck under lock in case a concurrent caller beat us to it.
	for _, t := range s.tried403 {
		if Hamming(t, sim) <= 2 {
			return
		}
	}
	s.tried403 = append(s.tried403, sim)
}

func NewScanner(cfg *Config, client *http.Client, target *url.URL, skip map[string]bool) *Scanner {
	if skip == nil {
		skip = map[string]bool{}
	}
	// Defensive clamps. cleanDir spawns exactly cfg.Concurrency workers and then feeds
	// candidates into an unbuffered channel: with Concurrency<=0 no workers exist, the
	// first send blocks forever, and the scan deadlocks silently on the first non-wall
	// candidate. calibrate() likewise produces an empty baseline when Probes<=0 (Profile
	// then flips Unusable and the whole dir is dropped without a hit ever being issued).
	// A library caller that forgets to set these, or a CLI operator passing `-c 0`, gets
	// a clean fallback instead of an unrecoverable hang or a coverage-blind dir.
	if cfg != nil {
		if cfg.Concurrency < 1 {
			cfg.Concurrency = 1
		}
		if cfg.Probes < 1 {
			cfg.Probes = 1
		}
	}
	s := &Scanner{cfg: cfg, client: client, target: target, skip: skip, nmSem: make(chan struct{}, 2)}
	if cfg != nil && cfg.HAROutput != "" {
		s.har = &harScope{}
	}
	// Open the checkpoint file in append mode. A failure here is non-fatal — the scan
	// still runs, we just lose crash-resilience. Warn so the operator sees it.
	if cfg != nil && cfg.CheckpointPath != "" {
		// 0600: the checkpoint carries every URL the scan hit — an operator on a shared
		// host doesn't want other users reading their target inventory. Mirrors -har and -o.
		f, err := os.OpenFile(cfg.CheckpointPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[33m[!] checkpoint %s: %v — resume disabled for this run\x1b[0m\n",
				cfg.CheckpointPath, err)
		} else {
			s.ckptFile = f
		}
	}
	return s
}

// Close releases the checkpoint file. Callers should defer this after NewScanner so the
// jsonl is fsync'd on a clean exit; the signal handler already drains temp files but does
// not know about this handle. Safe to call when no checkpoint was opened.
func (s *Scanner) Close() {
	if s == nil || s.ckptFile == nil {
		return
	}
	s.ckptFile.Close()
	s.ckptFile = nil
}

// HAREntries returns a snapshot of the scanner's HAR captures for main() to serialize.
// Nil-safe; returns nil when -har was not set (harScope was never allocated).
func (s *Scanner) HAREntries() []harCapture {
	if s == nil || s.har == nil {
		return nil
	}
	return s.har.snapshot()
}

// SeedFindings seeds the finding buffer with entries recovered from a prior checkpoint so
// the final report is cumulative across resumes rather than losing everything that was
// already recorded. Called from main.go after loadCheckpoint.
func (s *Scanner) SeedFindings(fs []Finding) {
	if len(fs) == 0 {
		return
	}
	s.mu.Lock()
	s.findings = append(s.findings, fs...)
	s.mu.Unlock()
}

// followShellHop returns r, or, when r is an empty-bodied on-host redirect,
// the response one hop past r. Used only for the shell-detection probes: those
// need a body signature to compare against, and a target root that answers with
// a 3xx (SPA behind /app/, SSO portal at /login, locale router at /en/) leaves
// SimHash("") = 0 in r.Sim, which silently disables kind:shell tagging in
// verify() and suppresses the catch-all warning. Bounded to a single hop and
// restricted to the target host — an off-scope redirect (r.OffScope, or a
// resolved Location on a different host) is left as-is so cfg.Headers/cfg.Proxy
// authentication never crosses origins.
func followShellHop(client *http.Client, target *url.URL, r Resp, cfg *Config) Resp {
	if r.Err != nil || r.OffScope || r.Sim != 0 || r.Via == "" {
		return r
	}
	loc, err := url.Parse(r.Via)
	if err != nil {
		return r
	}
	resolved := target.ResolveReference(loc)
	if resolved.Host != target.Host {
		return r
	}
	hop := fetch(client, target, resolved.String(), cfg)
	if hop.Err != nil || hop.OffScope {
		return r
	}
	return hop
}

func (s *Scanner) Run() []Finding {
	// 1) DISCOVERY — engines run in parallel; ferox/ffuf carry per-URL status (0 = unknown).
	//
	// Cache short-circuit: when -checkpoint is set AND a fresh sibling candidates.json
	// exists for the same target, skip every discovery engine. Discovery is most of the
	// wall time (ferox/ffuf/katana/gau/passive/openapi) and re-running it on a resume is
	// the loudest, slowest thing a "resume" can do. Freshness is target- and TTL-gated so
	// a stale cache can't silently ship old candidates as findings.
	union := map[string]cand{}
	targetKey := s.target.String()
	candPath := candidatesPath(s.cfg.CheckpointPath)
	usedCache := false
	if candPath != "" {
		if u, hit, err := loadCandidates(candPath, targetKey, s.cfg.ResumeTTL, s.cfg.ResumeCandidates); err != nil {
			// A malformed cache is not "no cache" — surface it so the operator sees it.
			fmt.Fprintf(os.Stderr, "\x1b[33m[!] candidate cache: %v — running discovery\x1b[0m\n", err)
		} else if hit {
			union = u
			usedCache = true
			fmt.Printf("[*] resume: reusing %d candidates from %s (skipping discovery engines)\n",
				len(union), candPath)
		}
	}
	var umu sync.Mutex
	add := func(u, src string, status int) {
		if n := norm(s.target, u); n != "" {
			umu.Lock()
			if _, ok := union[n]; !ok {
				union[n] = cand{n, src, status}
			}
			umu.Unlock()
		}
	}
	var ewg sync.WaitGroup
	var counts sync.Map
	runMap := func(tag, src string, fn func() map[string]int) {
		ewg.Add(1)
		go func() {
			defer ewg.Done()
			m := fn()
			counts.Store(tag, len(m))
			for u, st := range m {
				add(u, src, st)
			}
		}()
	}
	runList := func(tag, src string, fn func() []string) {
		ewg.Add(1)
		go func() {
			defer ewg.Done()
			l := fn()
			counts.Store(tag, len(l))
			for _, u := range l {
				add(u, src, 0)
			}
		}()
	}
	if !usedCache {
		if haveBin("feroxbuster") && s.cfg.Wordlist != "" {
			runMap("feroxbuster", "ferox", func() map[string]int { return runFerox(s.target.String(), s.cfg.Wordlist, s.cfg) })
		} else if haveBin("ffuf") && s.cfg.Wordlist != "" {
			runMap("ffuf", "ffuf", func() map[string]int { return runFfuf(s.target.String(), s.cfg.Wordlist, s.cfg) })
		}
		runList("katana", "katana", func() []string { return runKatana(s.target.String(), s.cfg) })
		runList("gau", "gau", func() []string {
			// gau is fed the target's Hostname() (broadest archive coverage — Wayback rarely
			// records ports). But Wayback normalizes archive URLs to the scheme default port,
			// so a target on :8443 that has /admin archived comes back as
			// https://example.com/admin — norm() would then discard it, because
			// example.com != example.com:8443. Graft the target's port onto every returned
			// URL whose hostname matches so the archive engine actually contributes on
			// non-default-port targets (staging/8443, dev/8080, IoT panels).
			urls := runGau(s.target.Hostname(), s.cfg)
			if s.target.Port() != "" {
				for i, u := range urls {
					urls[i] = graftPort(s.target, u)
				}
			}
			return urls
		})
		runList("passive", "passive", func() []string { return passivePaths(s.client, s.target, s.cfg) })
		runList("openapi", "openapi", func() []string { return openapiPaths(s.client, s.target, s.cfg) })
		ewg.Wait()
		add(s.target.String(), "seed", 0)
	}

	var used []string
	for _, tag := range []string{"feroxbuster", "ffuf", "gau", "katana", "passive", "openapi"} {
		if v, ok := counts.Load(tag); ok && v.(int) > 0 {
			used = append(used, fmt.Sprintf("%s(%d)", tag, v.(int)))
		}
	}
	if len(union) == 0 {
		fmt.Fprintln(os.Stderr, "no candidates — install/point an engine (feroxbuster+wordlist, katana, gau)")
		return nil
	}
	if s.cfg.MaxCandidates > 0 && len(union) > s.cfg.MaxCandidates {
		fmt.Printf("[!] %d candidates exceed cap %d — truncating\n", len(union), s.cfg.MaxCandidates)
		keys := make([]string, 0, len(union))
		for u := range union {
			keys = append(keys, u)
		}
		sort.Strings(keys)
		capped := map[string]cand{}
		for _, u := range keys[:s.cfg.MaxCandidates] {
			capped[u] = union[u]
		}
		union = capped
	}
	// Persist the discovery union so the next -checkpoint run can skip discovery. Only
	// write when we actually ran the engines this pass — writing after a cache-load is a
	// no-op that only bumps the timestamp (misleadingly refreshes the "fresh" window).
	if !usedCache && candPath != "" {
		if err := saveCandidates(candPath, targetKey, union); err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[33m[!] candidate cache write %s: %v\x1b[0m\n", candPath, err)
		}
	}
	if usedCache {
		fmt.Printf("[*] engines: cached  →  %d candidates to clean\n", len(union))
	} else {
		fmt.Printf("[*] engines: %s  →  %d candidates to clean\n", strings.Join(used, ", "), len(union))
	}

	// Load cached per-dir Profiles too (part of the resume contract). A cache hit means the
	// calibration probes on that dir are NOT re-issued — those are hits to the target that
	// resume was supposed to save. Root-URL bypass and catch-all detection are also skipped
	// on a hot resume, since they issue their own probes and re-running them defeats the
	// point of a resume for a hardened target.
	profPath := profilesPath(s.cfg.CheckpointPath)
	cachedProfiles := map[string]Profile{}
	if profPath != "" {
		if m, err := loadProfiles(profPath, targetKey, s.cfg.ResumeTTL, s.cfg.ResumeCandidates); err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[33m[!] profile cache: %v — calibrating from scratch\x1b[0m\n", err)
		} else if len(m) > 0 {
			cachedProfiles = m
			fmt.Printf("[*] resume: reusing %d directory calibrations from %s\n", len(cachedProfiles), profPath)
		}
	}

	// Catch-all/SPA detection: if the homepage and a random path return near-identical 200s, the
	// site serves one shell for everything — brute is low-signal and 200s may just be the shell.
	// Skipped when we resumed from cache — the root probes already ran on the prior invocation.
	if !usedCache {
		rawBase := fetch(s.client, s.target, s.target.String(), s.cfg)
		rnd := fetch(s.client, s.target, strings.TrimSuffix(s.target.String(), "/")+"/zz"+randToken(), s.cfg)
		// Redirect-fronted roots (SPAs behind /app/, SSO-gated apps, locale routers like `/`->`/en/`)
		// answer `/` with an empty-bodied 3xx; base.Sim then collapses to SimHash("")=0, s.baseSim=0,
		// and the shell guard `s.baseSim != 0 && ...` in verify() silently disables kind:shell tagging
		// for exactly the sites shell detection exists to defend against — every SPA route below
		// `/app/` ships as its own distinct 200 finding, and the catch-all warning stays silent
		// because both responses are 3xx. Follow ONE on-host hop for the shell probe only
		// (never off-scope: preserves the auth-header no-leak invariant fetch() already enforces).
		// rawBase is retained so the root-wall bypass probe still sees the original 401/403.
		base := followShellHop(s.client, s.target, rawBase, s.cfg)
		rnd = followShellHop(s.client, s.target, rnd, s.cfg)
		s.baseSim = base.Sim
		if base.Status == 200 && rnd.Status == 200 && Hamming(base.Sim, rnd.Sim) <= simhashDynamicSpread {
			fmt.Println("\x1b[33m[!] catch-all/SPA shell detected — brute is low-signal here; trust katana/JS endpoints, and treat kind:shell rows as the app shell, not distinct pages\x1b[0m")
		}
		// Root-URL bypass probe: if the target itself is behind a 401/403 wall (the whole app is
		// gated), that IS the bypass target — but the normal per-candidate judge would drop it as
		// "matches baseline". Try nomore403 on the root directly; a hit here is often the whole app.
		if s.cfg.Bypass && (rawBase.Status == 401 || rawBase.Status == 403) {
			if hit, ok := runNomore403(s.target.String(), s.cfg); ok {
				techStr := hit.String()
				// Root-wall probe runs before per-dir calibration, so there's no Profile to
				// compare against — build a one-sample ad-hoc profile from rawBase (the wall
				// response we're trying to bypass) with a tight threshold. A header replay
				// whose Sim leaves that envelope is a "verified" root-wall bypass; anything
				// else stays "unverified" as a lead the operator confirms by hand.
				// Threshold uses the same base margin as calibrated dirs (no observed spread
				// to add: the wall is one sample). This keeps the "how tight is 'in envelope'"
				// contract identical between the root probe and per-dir judges.
				wallProf := Profile{
					Statuses:  map[int]bool{rawBase.Status: true},
					Sims:      []uint64{rawBase.Sim},
					Threshold: simhashThresholdMargin,
				}
				bypass, preview := verifyBypass(s.client, s.target, s.target.String(), hit, wallProf, s.cfg, techStr)
				s.record(Finding{URL: s.target.String(), Status: rawBase.Status, Len: rawBase.Len,
					Source: "seed", Via: rawBase.Via, Sim: rawBase.Sim, Dist: 64,
					Bypass: bypass, BypassPreview: preview, Note: "root-wall-bypass"})
			}
		}
	}

	// 2) group by directory so each gets its own SimHash not-found calibration
	byDir := map[string][]cand{}
	for u, c := range union {
		byDir[dirOf(u)] = append(byDir[dirOf(u)], c)
	}

	// 3) CLEAN — per directory: calibrate the soft-404 profile (or reuse the cached one),
	// then judge every candidate.
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	freshProfiles := map[string]Profile{}
	for _, dir := range dirs {
		p, cached := cachedProfiles[dir]
		if !cached {
			p = calibrate(s.client, s.target, dir, s.cfg)
		}
		// A profile trained on too few successful probes has no signal — judging against it would
		// promote every candidate to VHit. Drop the dir loudly rather than emit engine noise as hits.
		if p.Unusable {
			fmt.Printf("\x1b[31m[!] %s  calibration failed (probes=%d ok=%d) — dropping %d candidates from this dir\x1b[0m\n",
				dir, s.cfg.Probes, len(p.Sims), len(byDir[dir]))
			continue
		}
		mode := "static"
		if p.Dynamic {
			mode = "dynamic"
		}
		src := "calibrated"
		if cached {
			src = "cached"
		}
		fmt.Printf("\x1b[36m[*] %s  baseline=%v thr=%d (%s, %s)  n=%d\x1b[0m\n",
			dir, statusKeys(p.Statuses), p.Threshold, mode, src, len(byDir[dir]))
		freshProfiles[dir] = p
		s.cleanDir(dir, byDir[dir], p)
	}
	// Persist the (possibly extended) profile map for the next resume. Save non-Unusable
	// profiles that either came in fresh or were carried over — anything Unusable was
	// deliberately dropped and shouldn't be handed to a future run as if it were valid.
	if profPath != "" && len(freshProfiles) > 0 {
		if err := saveProfiles(profPath, targetKey, freshProfiles); err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[33m[!] profile cache write %s: %v\x1b[0m\n", profPath, err)
		}
	}

	// End-of-run fetch-health check. Two ways the scan is called blind:
	//   (a) any single dir where every attempted fetch failed — the operator has no
	//       signal for that whole slice of the site;
	//   (b) global error rate above fetchErrsThreshold — a systemic break (network,
	//       WAF, TLS) that makes the whole "0 findings" summary meaningless.
	// Either flips cfg.Truncated so `coverage:` prints PARTIAL and the JSON meta says
	// so — the same channel -engine-timeout already uses.
	tot := s.attempts.Load()
	errs := s.fetchErrs.Load()
	if tot > 0 && float64(errs)/float64(tot) > fetchErrThreshold {
		fmt.Fprintf(os.Stderr,
			"\x1b[31m[!] coverage: PARTIAL — %d/%d candidates failed to fetch (network/WAF/TLS?)\x1b[0m\n",
			errs, tot)
		s.cfg.Truncated.Store(true)
	}
	return s.findings
}

// wallOf reports whether a directory's not-found profile is a single static 401/403 — an auth/WAF
// wall — so engine-reported hits with that status can be collapsed instead of re-fetched.
func wallOf(p Profile) (int, bool) {
	if len(p.Statuses) != 1 || p.Dynamic {
		return 0, false
	}
	for st := range p.Statuses {
		if st == 401 || st == 403 {
			return st, true
		}
	}
	return 0, false
}

func (s *Scanner) cleanDir(dir string, cands []cand, p Profile) {
	// Uniform-wall shortcut: if this directory's not-found is a single, static 401/403 (a WAF/auth
	// wall), candidates the engine already saw with that same status ARE the wall — don't re-fetch
	// thousands of them just to SimHash-confirm it. Collapse them into one row; still verify anything
	// with a different (or unknown) status, so an outlier like /ping 200 is never missed.
	wallStatus, isWall := wallOf(p)

	// Per-dir fetch-health counters. If every attempted fetch on this dir errors (WAF drops
	// the whole prefix, DNS breaks, TLS regression on one vhost), we're blind on the entire
	// slice — flip Truncated even if the global rate is still under threshold.
	var dirAttempts, dirErrs atomic.Int64

	ch := make(chan cand)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range ch {
				s.verify(c, p, &dirAttempts, &dirErrs)
			}
		}()
	}
	var wall []string
	for _, c := range cands {
		// Resume contract: a URL the previous run already emitted MUST NOT reappear this pass.
		// verify() honors skip{}, but the wall shortcut used to bypass it — so on --resume, a
		// URL the operator already saw as a wall representative or wall member would be re-added
		// to the new wall Finding's Members (and could re-emit as the representative itself).
		// Filter skip{} FIRST so both the wall bucket and verify() see the same additive view.
		if s.skip[c.url] {
			continue
		}
		// Sensitive paths (.git, .env, actuator/env, heapdump, wp-config, …) NEVER go into the wall
		// bucket. A silent skip here would hide a real exposure — always verify them.
		if isWall && c.status == wallStatus && !isSensitive(c.url) {
			wall = append(wall, c.url)
			continue
		}
		ch <- c
	}
	close(ch)
	wg.Wait()

	if len(wall) > 0 {
		sort.Strings(wall)
		s.record(Finding{URL: wall[0], Status: wallStatus, Source: "engine-status",
			Type: "uniform-wall", Collapsed: len(wall), Members: wall})
	}

	if a := dirAttempts.Load(); a > 0 && dirErrs.Load() == a {
		fmt.Fprintf(os.Stderr,
			"\x1b[31m[!] %s  all %d candidates failed to fetch — dir is blind\x1b[0m\n", dir, a)
		s.cfg.Truncated.Store(true)
	}
}

func (s *Scanner) verify(c cand, p Profile, dirAttempts, dirErrs *atomic.Int64) {
	if s.skip[c.url] {
		return
	}
	r := fetch(s.client, s.target, c.url, s.cfg)
	// Count every attempted fetch — but only unexpected errors count against coverage.
	// OffScope (an on-purpose off-host redirect) is real and expected: excluding it means
	// a target that legitimately fans out cross-host doesn't get mislabelled PARTIAL.
	dirAttempts.Add(1)
	s.attempts.Add(1)
	if r.OffScope {
		return
	}
	if r.Err != nil {
		dirErrs.Add(1)
		s.fetchErrs.Add(1)
		return
	}

	// Realtime-endpoint promotion. Plain GETs against WebSocket URLs return 400/426
	// (or a naked 200 hello page), so the profile judge would otherwise class them
	// like any other page and /ws, /socket.io, /events could vanish into the noise —
	// on an API-heavy target the whole realtime surface (chat, MQTT-over-WS, control
	// channels) sits on that one 101 handshake.
	//   - text/event-stream (SSE) is visible from the plain GET response headers.
	//   - WebSocket needs a same-URL retry with Upgrade headers; fire it when the
	//     path names a realtime convention or the GET already screamed "wrong method".
	sseHit := strings.HasPrefix(strings.ToLower(r.CType), "text/event-stream")
	if !sseHit && r.Status != 101 && (r.Status == 400 || r.Status == 426 || wsPathHint(c.url)) {
		if code, err := wsProbe(s.target, c.url, s.cfg); err == nil && code == 101 {
			r.Status = 101
		}
	}

	v, dist := p.judge(r)
	if v == VNotFound {
		return
	}
	// HAR capture happens BEFORE we decide "hit vs review vs bypass" — the export is a per-URL
	// snapshot for manual replay, so the operator wants the raw request/response regardless of
	// how sift categorized it. Skipped when -har is off (s.har is nil).
	if s.har != nil {
		body := r.Body
		if len(body) > harBodyCap {
			body = body[:harBodyCap]
		}
		s.har.add(harCapture{
			URL:         c.url,
			Method:      "GET",
			ReqHeaders:  s.cfg.Headers,
			Status:      r.Status,
			CType:       r.CType,
			Body:        body,
			RespHeaders: r.Headers, // set by fetch() when cfg.HAROutput != ""; nil otherwise
		})
	}
	f := Finding{URL: c.url, Status: r.Status, Len: r.Len, Source: c.source, Via: r.Via,
		Sim: r.Sim, Dist: dist, Title: r.Title, Type: r.CType}
	switch {
	case r.Status == 101:
		f.Kind = "ws" // WebSocket handshake accepted — the realtime surface lives here
	case sseHit:
		f.Kind = "sse" // Server-Sent Events stream
	case isAsset(c.url):
		f.Kind = "asset"
	case s.baseSim != 0 && r.Status == 200 && c.url != s.target.String() && Hamming(r.Sim, s.baseSim) <= simhashThresholdMargin:
		f.Kind = "shell" // a 200 that's just the app/SPA shell (the homepage itself is exempt)
	}

	// Sensitive-path WAF-block probe: a 403 on /.env or /.git could be a real block on the file OR
	// a name-based WAF rule that fires on the *pattern*. Fetch a same-shape decoy — a random suffix
	// that couldn't exist as a real file. Two ways the 403 proves to be name-based (not exposure):
	//   (a) decoy returns the SAME 403 with a matching body — the WAF blocks the whole pattern; or
	//   (b) decoy returns a totally DIFFERENT status (e.g. 200 SPA shell / 404) — the WAF singled
	//       out the sensitive name and let the fake through. Either way, it's a WAF pattern rule.
	if (r.Status == 401 || r.Status == 403) && isSensitive(c.url) {
		decoy := decoyFor(c.url)
		if decoy != "" {
			d := fetch(s.client, s.target, decoy, s.cfg)
			if d.Err == nil {
				sameBlock := d.Status == r.Status && Hamming(d.Sim, r.Sim) <= simhashThresholdMargin
				decoyPassed := d.Status != r.Status
				if sameBlock || decoyPassed {
					f.Note = "waf-pattern-block"
				}
			}
		}
	}
	// Secret-pattern scan on successful text/JSON bodies (leads, not confirmations). Skipped for
	// assets — minified JS bundles trip generic-secret regexes ~100% of the time and drown real leads.
	if r.Status >= 200 && r.Status < 400 && r.Body != "" && f.Kind != "asset" {
		if secs := scanSecrets(r.Body, r.CType); len(secs) > 0 {
			f.Secrets = secs
		}
	}

	if v == VReview {
		f.Review = true
		s.record(f)
		return
	}
	if (r.Status == 401 || r.Status == 403) && !s.bypassTried(r.Sim) && f.Note != "waf-pattern-block" {
		s.nmSem <- struct{}{}
		hit, ok, transient := runNomore403WithStatus(c.url, s.cfg)
		<-s.nmSem
		// Only mark this signature as "tried" when nomore403 actually completed. A transient
		// failure (timeout, unparseable JSON, network hiccup) should NOT permanently disable
		// retries for the same WAF body on subsequent 403s.
		if !transient {
			s.markBypassTried(r.Sim)
		}
		if ok {
			// For the header technique nomore403 can win with (X-Forwarded-For: 127.0.0.1,
			// X-Original-URL: /, …) sift can replay the exact request in-process — the
			// payload is a single "Name: value" pair. verifyBypass runs the replay through
			// the same fetch() plumbing, then asks the dir's Profile whether the response
			// is still inside the not-found envelope.
			f.Bypass, f.BypassPreview = verifyBypass(s.client, s.target, c.url, hit, p, s.cfg, hit.String())
		}
	}
	s.record(f)
}

// verifyBypass replays a nomore403 winning record when the technique is safely
// reproducible in-process, then checks whether the response leaves the not-found
// envelope (the same p.isNotFound sift already uses to distinguish a real page
// from a soft-404). Returns the Bypass label ("verified:*" or "unverified:*") and,
// on verified hits, a compact HTML-escaped body preview so the operator can tell a
// real bypass from a login page or WAF happy-path without hand-replaying.
//
// Only the "headers" technique is replayed today: the payload is a plain "Name: value"
// pair and a GET with that extra header is a trivial rebuild of nomore403's request.
// verb tunneling, endpaths, path-case and any future technique that would need a
// non-GET verb, a mangled path, or a different transport stay as "unverified:*" —
// silently misreproducing them is worse than not verifying.
func verifyBypass(client *http.Client, target *url.URL, rawurl string, hit *NomoreHit, p Profile, cfg *Config, techStr string) (string, string) {
	if hit == nil {
		return "", ""
	}
	if hit.Technique != "headers" {
		return "unverified:" + techStr, ""
	}
	name, val, ok := splitHeaderPayload(hit.Payload)
	if !ok {
		return "unverified:" + techStr, ""
	}
	r := fetchWith(client, target, rawurl, cfg, map[string]string{name: val})
	if r.Err != nil || r.OffScope {
		// Any transport failure means we can't prove anything about the bypass — keep it
		// as a lead, don't downgrade a real hit just because the replay hit a network blip.
		return "unverified:" + techStr, ""
	}
	if r.Status < 200 || r.Status >= 300 {
		// Replay disagreed with nomore403 — the winning 2xx wasn't reproducible from our
		// vantage point (rate limit, sticky session, ephemeral WAF decision). Lead only.
		return "unverified:" + techStr, ""
	}
	if p.isNotFound(r) {
		// Same not-found envelope — the "bypass" is a login page or WAF happy-path.
		// Keep the label as a lead so the operator sees the technique fired but knows
		// it didn't clear the wall.
		return "unverified:" + techStr, ""
	}
	return "verified:" + techStr, buildBypassPreview(r)
}

// splitHeaderPayload parses nomore403's headers-technique payload ("Header-Name: value")
// into a name/value pair usable with http.Header.Set. Returns ok=false on any payload
// that's missing a colon or empty on either side — those go back through the "unverified"
// path rather than sending a malformed request.
func splitHeaderPayload(payload string) (string, string, bool) {
	i := strings.Index(payload, ":")
	if i <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(payload[:i])
	val := strings.TrimSpace(payload[i+1:])
	if name == "" {
		return "", "", false
	}
	return name, val, true
}

// buildBypassPreview is the compact HTML-escaped snapshot recorded on a verified bypass.
// Title first (the discriminator that already survived extractTitle's normalization), then
// up to the first 200 chars of the body — enough to see "Admin dashboard" vs "Please log in"
// without shipping a 2 MB body into the JSON report.
func buildBypassPreview(r Resp) string {
	const bodyCap = 200
	body := r.Body
	if len(body) > bodyCap {
		body = body[:bodyCap]
	}
	// Whitespace-collapse the body slice so the preview stays on one line in the terminal.
	body = strings.Join(strings.Fields(body), " ")
	esc := html.EscapeString(body)
	if r.Title != "" {
		return "title=" + html.EscapeString(r.Title) + " | " + esc
	}
	return esc
}

func (s *Scanner) record(f Finding) {
	s.mu.Lock()
	s.findings = append(s.findings, f)
	// Append to the checkpoint jsonl under the same lock: if the process is killed here
	// the next -checkpoint run picks up exactly these findings and skip{}s their URLs.
	// Marshal errors on a Finding are effectively unreachable (Finding is all primitive
	// fields), but we still guard so a serialization surprise never crashes a live scan.
	if s.ckptFile != nil {
		if b, err := json.Marshal(&f); err == nil {
			s.ckptFile.Write(b)
			s.ckptFile.Write([]byte{'\n'})
		}
	}
	s.mu.Unlock()
	if f.Review {
		fmt.Printf("  \x1b[33m[?%d] %s\x1b[0m \x1b[90m(%s)\x1b[0m \x1b[33m[review]\x1b[0m\n", f.Status, f.URL, f.Source)
		return
	}
	col := 32
	if f.Status >= 400 {
		col = 31
	} else if f.Status >= 300 {
		col = 36
	}
	extra := ""
	if f.Via != "" {
		extra += " \x1b[36m-> " + f.Via + "\x1b[0m"
	}
	if f.Bypass != "" {
		extra += " \x1b[32;1m[BYPASS " + f.Bypass + "]\x1b[0m"
	}
	if f.Kind != "" {
		extra += " \x1b[35m[" + f.Kind + "]\x1b[0m"
	}
	if len(f.Secrets) > 0 {
		extra += " \x1b[31;1m[SECRET " + strings.Join(f.Secrets, ",") + "]\x1b[0m"
	}
	if f.Note != "" {
		extra += " \x1b[90m[" + f.Note + "]\x1b[0m"
	}
	fmt.Printf("  \x1b[%dm[%d] %s\x1b[0m \x1b[90m(%s d%d)\x1b[0m%s\n", col, f.Status, f.URL, f.Source, f.Dist, extra)
}
