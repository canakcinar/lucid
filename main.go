package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var assetRe = regexp.MustCompile(`(?i)\.(jpg|jpeg|jfif|png|gif|svg|webp|ico|css|js|mjs|map|mp4|webm|mp3|pdf|woff2?|ttf|eot|zip|gz|xml)(\?|$)`)

func isAsset(u string) bool { return assetRe.MatchString(u) }

// version is patched at build time via `-ldflags "-X main.version=v0.1.0"`. Left as "dev"
// for `go build ./...` and `go run .` so a source-tree build never lies about being a tagged
// release. Consumed by -version, the HAR creator field, and the default -ua string.
var version = "dev"

// collapse merges findings that share the same status AND a near-identical body (Hamming ≤ 2)
// into a single representative when the cluster is large — e.g. one WAF/Cloudflare 403 block
// page returned for dozens of blocked paths. Uses the SimHash core; distinct pages never merge.
func collapse(fs []Finding, minN int) []Finding {
	if minN <= 0 {
		return fs
	}
	used := make([]bool, len(fs))
	var out []Finding
	for i := range fs {
		if used[i] {
			continue
		}
		cluster := []int{i}
		for j := i + 1; j < len(fs); j++ {
			if used[j] || fs[j].Status != fs[i].Status || Hamming(fs[i].Sim, fs[j].Sim) > 2 {
				continue
			}
			// SimHash(0) is the sentinel for an empty body — every empty-body finding
			// hashes to 0 and would otherwise Hamming-collide with every other empty-body
			// finding of the same status (very common: nginx `return 302 /login;`
			// redirects, 204 No Content, empty 401/403 backends). Two such findings with
			// different redirect targets or content types are NOT the same response — the
			// only per-URL data an empty body carries is Via/Type, so require those to
			// match before merging, otherwise /admin→/login and /users→/error silently
			// collapse into one row that reports only one Location.
			if fs[i].Sim == 0 && fs[j].Sim == 0 {
				if fs[i].Via != fs[j].Via || fs[i].Type != fs[j].Type {
					continue
				}
			}
			cluster = append(cluster, j)
		}
		if len(cluster) >= minN {
			rep := fs[i]
			// Accumulate members and counts from scratch. Some cluster members may already be
			// clusters themselves (e.g. scanner.cleanDir emits one uniform-wall Finding per dir
			// with Collapsed=N + Members=[all N wall URLs]; those Findings share Sim=0 so they
			// re-cluster here). Preserve their true Members and Collapsed rather than treating
			// each as a single URL — otherwise the wall URLs from all but the representative
			// directory silently vanish, and Collapsed reports the cluster size instead of the
			// real number of collapsed paths.
			var members []string
			count := 0
			// Note is per-URL evidence (e.g. "waf-pattern-block" means the decoy probe proved
			// this specific 403 was a name-based WAF filter, not a real exposure). It CANNOT
			// be propagated across cluster members: a mixed cluster where /admin returns a
			// genuine 403 (Note="") and /wp-config.php returns a waf-pattern-block would
			// otherwise inherit the WAF tag onto the real finding — the exact case the
			// sensitive-path guard exists to prevent. All-or-nothing: keep rep.Note only if
			// every member of the cluster carries the same Note; otherwise clear it.
			firstNote := fs[i].Note
			noteAgrees := true
			for _, k := range cluster {
				used[k] = true
				if fs[k].Collapsed > 0 {
					count += fs[k].Collapsed
					members = append(members, fs[k].Members...)
				} else {
					count++
					members = append(members, fs[k].URL) // keep every collapsed URL in the JSON
				}
				if fs[k].Note != firstNote {
					noteAgrees = false
				}
				// Preserve distinguishing per-member data that would otherwise vanish onto
				// the representative. "shell" outranks any other Kind (a real app shell must
				// not be hidden inside a WAF-wall aggregate). Bypass fires rarely; keep the
				// first non-empty. Secrets are per-URL leads, so union them across the cluster.
				if fs[k].Kind == "shell" && rep.Kind != "shell" {
					rep.Kind = "shell"
				}
				if rep.Bypass == "" && fs[k].Bypass != "" {
					rep.Bypass = fs[k].Bypass
				}
				for _, s := range fs[k].Secrets {
					dup := false
					for _, e := range rep.Secrets {
						if e == s {
							dup = true
							break
						}
					}
					if !dup {
						rep.Secrets = append(rep.Secrets, s)
					}
				}
			}
			if !noteAgrees {
				rep.Note = ""
			}
			rep.Collapsed = count
			rep.Members = members
			out = append(out, rep)
		} else {
			used[i] = true
			out = append(out, fs[i])
		}
	}
	return out
}

type Config struct {
	Concurrency int
	Timeout     int
	Proxy       string
	Insecure    bool
	UA          string
	Headers     map[string]string
	Probes      int
	Threshold   int
	MaxDepth    int
	Exts        []string
	Bypass       bool
	Archive      bool
	Delay        int
	ReviewMargin int
	Wordlist      string
	MaxReq        int
	Rate          int
	EngineTimeout int
	MaxCandidates int
	Assets        bool
	Collapse      int
	HAROutput     string // -har: write a HAR 1.2 export of every Finding's request/response

	// --- runtime state below. Do NOT read/write these from outside sift; use ResetRuntime()
	// to clear them before reusing a Config for another scan. Keeping them on Config (rather
	// than a separate Runtime struct) keeps the surface small; ResetRuntime() is the seam.
	reqCount int64
	Throttle *Throttle
	// Truncated is set when any external engine hit -engine-timeout. Per-Config (not global)
	// so a second scan in the same process starts clean — critical when sift is used as a
	// library or when -audit runs before a real scan.
	Truncated atomic.Bool
	// PartialReason records WHICH engine truncated when Truncated flips true. Written by
	// truncWarn / engineRunErr / verify(); consumed by main.go to populate meta.partial_reason
	// in the -o JSON. A CI script gating on coverage:partial needs to know if it was
	// ferox_timeout (raise -engine-timeout) or fetch_errors (network flaky) to decide whether
	// to retry — a bare "partial" gave no direction. Concurrent writers protected by partialMu.
	PartialReason  string
	partialMu      sync.Mutex
	// engineTimeoutSetByUser is true when the operator passed -engine-timeout on the CLI. When
	// unset, engineCmdBudget uses the per-engine derived budget (feroxBudget / nomoreBudget);
	// when set, the operator's number wins so an exotic case (slow VPN, paranoid rate) can
	// override without a code change.
	engineTimeoutSetByUser bool

	// Mode selects the ferox aggressiveness profile:
	//   - "fast"     : ferox --no-recursion, extensions IGNORED (wordlist only). Cheapest;
	//                  best for a first-look sweep across many hosts.
	//   - "standard" : ferox --no-recursion, extensions applied (default). Recursion is
	//                  katana's job; ferox does one clean pass over the wordlist × exts.
	//   - "deep"     : ferox recurses (respects MaxDepth), extensions applied. Slowest;
	//                  use when you know the target has unlinked sub-directories that
	//                  katana can't see and are worth blind brute.
	// The mode drives runFerox's argv AND feroxBudget's deadline formula — the two MUST
	// stay in sync or the fast mode will hit a deadline meant for the deep mode.
	Mode string

	// Resume/checkpoint plumbing. CheckpointPath, when set, makes the scanner:
	//   - open the file in append mode and write one Finding per line inside record()
	//   - cache the discovery union to <CheckpointPath>.candidates.json
	//   - cache per-dir calibration Profiles to <CheckpointPath>.profiles.json
	// ResumeTTL bounds how long the two sibling caches are considered fresh (seconds; 0 =
	// never expires). ResumeCandidates forces reuse regardless of TTL.
	CheckpointPath   string
	ResumeCandidates bool
	ResumeTTL        int
}

// ResetRuntime clears every per-scan bit of state hanging off Config (request counter,
// truncation flag, throttle). Library consumers running back-to-back scans against the
// same Config MUST call this between runs — otherwise a PARTIAL from run N marks run N+1
// as PARTIAL too, and the request budget appears already-spent. Callers keep their
// user-set flags (Concurrency, Wordlist, Rate, ...) untouched.
func (c *Config) ResetRuntime() {
	atomic.StoreInt64(&c.reqCount, 0)
	c.Truncated.Store(false)
	c.partialMu.Lock()
	c.PartialReason = ""
	c.partialMu.Unlock()
	// Throttle carries its own accumulated backoff; a fresh scan should start at the base.
	// Only rebuild it if Delay is set — Delay==0 means "no throttling", and a nil Throttle
	// is the honest representation of that (fetch.go tolerates cfg.Throttle == nil).
	if c.Delay > 0 {
		c.Throttle = NewThrottle(c.Delay)
	} else {
		c.Throttle = nil
	}
}

type Finding struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Len    int    `json:"len"`
	Source string `json:"source"`
	Via       string `json:"via,omitempty"`
	Kind      string `json:"kind,omitempty"` // "asset" | "shell"
	Type      string `json:"type,omitempty"` // content-type
	Title     string `json:"title,omitempty"`
	Dist      int    `json:"dist,omitempty"` // SimHash distance from not-found (confidence)
	Bypass    string `json:"bypass,omitempty"`
	// BypassPreview is populated only when Bypass is "verified:*" — sift replayed the winning
	// nomore403 request in-process, confirmed the response left the not-found envelope, and
	// captured a short snapshot (title + first ~200 chars, HTML-escaped) so the operator can
	// tell a real bypass from a login page or WAF happy-path without hand-replaying. Empty
	// for "unverified:*" hits (verb-tunneling and other techniques sift can't safely rebuild).
	BypassPreview string `json:"bypass_preview,omitempty"`
	Review    bool     `json:"review,omitempty"`
	Collapsed int      `json:"collapsed,omitempty"` // this row stands in for N same-response paths
	Members   []string `json:"members,omitempty"`   // the collapsed URLs — nothing is lost
	Secrets   []string `json:"secrets,omitempty"`   // fired secret-pattern names — leads, not confirmations
	Note      string   `json:"note,omitempty"`      // e.g. "waf-pattern-block" for a sensitive-path 403 that's just a filter
	New       bool     `json:"new,omitempty"`
	// Change is set alongside New when -diff finds a URL in the baseline whose observable
	// signal (Status/Kind/Bypass) differs from this run. Empty when the URL is genuinely
	// unseen — that's the historical "new-url" case, and callers can still branch on !=""
	// to tell drift ("status:200->403") from truly new endpoints. Serialized only when set.
	Change    string   `json:"change,omitempty"`
	Sim       uint64   `json:"-"`                   // SimHash, used for clustering; not serialized
}

// loadBaseline reads a prior findings file and returns the per-URL Finding it contains.
// Returns an error when the file is unreadable OR the JSON can't be parsed as either
// supported shape — silently returning an empty map makes --resume rescan everything
// and --diff mark every finding new, both of which are worse than an obvious failure.
//
// The map value carries the full Finding so -diff can compare Status/Kind/Bypass (not
// just presence): a URL flipping 200→403, gaining a Bypass, or a shell being reclassified
// as an asset is a regression the operator needs to see, but the older set-of-URLs shape
// hid it behind "already in baseline". Callers that only need URL presence iterate keys.
func loadBaseline(path string) (map[string]Finding, error) {
	m := map[string]Finding{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	// Accept both shapes: the current {meta, findings} wrapper and the earlier bare array.
	// Pointer, not slice — distinguishes "no findings key" from "findings:[]". A wrapped
	// run with 0 findings is legitimate and must not fall through to the array parse.
	var wrapped struct {
		Findings *[]Finding `json:"findings"`
	}
	if werr := json.Unmarshal(b, &wrapped); werr == nil && wrapped.Findings != nil {
		for _, f := range *wrapped.Findings {
			m[f.URL] = f
		}
		return m, nil
	}
	var prev []Finding
	if perr := json.Unmarshal(b, &prev); perr == nil {
		for _, f := range prev {
			m[f.URL] = f
		}
		return m, nil
	}
	return m, fmt.Errorf("baseline %s: not valid sift JSON (expected {\"findings\":[...]} or [Finding,...])", path)
}

// diffAgainstBaseline compares a live finding to its baseline entry (if any) and returns
// whether the run should tag it as changed, plus a compact reason string for the console.
// Kept as a small named function so the -diff loop stays readable and the semantics live
// in one place: new URL, status flip, kind flip (e.g. shell demoted to asset), or a bypass
// gained/lost. Anything more subtle (Len, Title, Secrets union) is deliberately excluded
// — those change on normal churn and would spam the "NEW" tag with noise.
func diffAgainstBaseline(cur Finding, prev map[string]Finding) (bool, string) {
	base, ok := prev[cur.URL]
	if !ok {
		return true, "new-url"
	}
	var changes []string
	if base.Status != cur.Status {
		changes = append(changes, fmt.Sprintf("status:%d->%d", base.Status, cur.Status))
	}
	if base.Kind != cur.Kind {
		changes = append(changes, fmt.Sprintf("kind:%q->%q", base.Kind, cur.Kind))
	}
	if base.Bypass != cur.Bypass {
		switch {
		case base.Bypass == "" && cur.Bypass != "":
			changes = append(changes, "bypass-added")
		case base.Bypass != "" && cur.Bypass == "":
			changes = append(changes, "bypass-removed")
		default:
			changes = append(changes, "bypass-changed")
		}
	}
	if len(changes) == 0 {
		return false, ""
	}
	return true, strings.Join(changes, ",")
}

type headerFlags []string

func (h *headerFlags) String() string     { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error { *h = append(*h, v); return nil }

// graftPort returns u with the target's port grafted onto it when u's hostname matches the
// target but u carries no explicit port (or the same port already). Exists because gau/Wayback
// normalize archive URLs to the scheme's default port — a target on :8443 that has /admin
// archived comes back as https://example.com/admin, which norm() would then discard because
// example.com != example.com:8443. Never rewrites a URL that names a different explicit port
// (that's a genuinely different host in norm()'s sense) or one whose hostname differs.
func graftPort(target *url.URL, u string) string {
	if target == nil || target.Port() == "" || u == "" {
		return u
	}
	ref, err := url.Parse(u)
	if err != nil || ref.Host == "" {
		return u
	}
	if !strings.EqualFold(ref.Hostname(), target.Hostname()) {
		return u
	}
	if p := ref.Port(); p != "" && p != target.Port() {
		return u
	}
	ref.Host = target.Host
	return ref.String()
}

// norm resolves a raw path/URL against the target and keeps it only if it stays on host.
func norm(target *url.URL, p string) string {
	p = strings.TrimSpace(p)
	if p == "" || strings.HasPrefix(p, "#") {
		return ""
	}
	ref, err := url.Parse(p)
	if err != nil {
		return ""
	}
	abs := target.ResolveReference(ref)
	if abs.Host != target.Host || (abs.Scheme != "http" && abs.Scheme != "https") {
		return ""
	}
	abs.Fragment = "" // keep the query: parameterized endpoints from katana/gau are real targets
	return abs.String()
}

// dirOf returns the directory a URL belongs to, parsed properly (no scheme magic numbers).
func dirOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := strings.TrimSuffix(u.Path, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[:i+1]
	} else {
		p = "/"
	}
	u.Path, u.RawQuery, u.Fragment = p, "", ""
	return u.String()
}

func statusKeys(m map[int]bool) []int {
	var s []int
	for k := range m {
		s = append(s, k)
	}
	sort.Ints(s)
	return s
}

func main() {
	// Wire SIGINT/SIGTERM into rootCtx so a Ctrl-C (interactive) or systemd/nohup
	// SIGTERM (non-interactive) tears down every engine's context, kills their
	// process groups, and drains the temp-file registry — without this every
	// interrupted scan leaks sift-ferox-*.jsonl / sift-ffuf-*.json / sift-nm-*.json
	// into $TMPDIR and can orphan feroxbuster/katana/gau/nomore403 processes.
	defer installSignalHandler()()

	cfg := &Config{Headers: map[string]string{}}
	flag.IntVar(&cfg.Concurrency, "c", 20, "concurrent requests")
	flag.IntVar(&cfg.Timeout, "t", 15, "request timeout (seconds)")
	flag.StringVar(&cfg.Proxy, "x", "", "proxy url (e.g. http://127.0.0.1:8080)")
	flag.BoolVar(&cfg.Insecure, "k", true, "skip TLS verification")
	flag.IntVar(&cfg.Probes, "probes", 4, "calibration probes per directory")
	flag.IntVar(&cfg.Threshold, "threshold", -1, "simhash hamming threshold (-1 = auto)")
	flag.IntVar(&cfg.MaxDepth, "depth", 2, "recursion depth (0 = no recursion)")
	flag.BoolVar(&cfg.Bypass, "bypass", true, "run nomore403 on 403/401 findings if installed")
	flag.StringVar(&cfg.Mode, "mode", "standard",
		"ferox aggressiveness: fast (no ext, no recursion) | standard (ext, no recursion) | deep (ext, recursion)")
	auditMode := flag.Bool("audit", false, "run integration audit (stands up a local mock, exercises every engine) and exit")
	versionFlag := flag.Bool("version", false, "print the sift version and exit")
	flag.BoolVar(&cfg.Archive, "archive", true, "pull historical paths via gau if installed")
	flag.IntVar(&cfg.Delay, "delay", 0, "base delay per request (ms); auto-backoff on 429/503")
	flag.IntVar(&cfg.ReviewMargin, "review", 2, "review-band width just inside threshold (0 = off)")
	flag.IntVar(&cfg.MaxReq, "budget", 0, "max total sift cleanup requests (0 = unlimited)")
	flag.IntVar(&cfg.Rate, "rate", 0, "req/s cap passed to engines + sift (0 = unlimited)")
	flag.IntVar(&cfg.EngineTimeout, "engine-timeout", 300, "per-engine hard timeout (seconds)")
	flag.IntVar(&cfg.MaxCandidates, "max-candidates", 20000, "cap on candidate URLs to clean (0 = unlimited)")
	flag.BoolVar(&cfg.Assets, "assets", true, "include static assets (js/css/img/pdf…) in findings")
	flag.IntVar(&cfg.Collapse, "collapse", 5, "merge N+ findings sharing an identical response (0 = off)")
	flag.StringVar(&cfg.HAROutput, "har", "", "write a HAR 1.2 export of every Finding's request/response (Cookie/Authorization redacted)")
	harRequired := flag.Bool("har-required", false, "exit nonzero if -har was set but writing the HAR failed (default: warn+continue)")
	oRequired := flag.Bool("o-required", false, "exit nonzero if -o was set but writing the JSON failed (default: warn+continue)")
	exts := flag.String("e", "", "extensions to append, comma-separated (e.g. php,html,json)")
	wordlist := flag.String("w", "", "wordlist file")
	outfile := flag.String("o", "", "write findings as JSON to this file")
	diffFile := flag.String("diff", "", "baseline JSON from a previous run; tag paths not in it as new")
	resumeFile := flag.String("resume", "", "prior findings JSON; skip URLs already in it")
	// -checkpoint is the two-file resume contract (jsonl of findings + sibling candidate/profile
	// caches). Given -checkpoint alone, a crashed/killed scan can pick up mid-run: skip{} is
	// seeded from every recorded URL and discovery/calibration are reused from disk.
	flag.StringVar(&cfg.CheckpointPath, "checkpoint", "",
		"jsonl checkpoint file (findings appended live; siblings .candidates.json/.profiles.json cache discovery+calibration)")
	flag.IntVar(&cfg.ResumeTTL, "resume-ttl", 86400,
		"seconds discovery/calibration caches stay fresh (0 = never expires)")
	flag.BoolVar(&cfg.ResumeCandidates, "resume-candidates", false,
		"force reuse of the candidate/profile caches even if -resume-ttl expired")
	cookie := flag.String("b", "", "Cookie header value (auth)")
	// -u is a first-class HTTP Basic flag. Enterprise IoT / API / admin panels commonly sit
	// behind Basic; without this users hand-craft -H "Authorization: Basic <b64>" and encode
	// the creds themselves — the classic misconfiguration where the header is mistyped, every
	// candidate silently comes back 401, the calibrator learns that as the baseline, and every
	// real endpoint gets dropped as "not found". A blank password is refused unless the caller
	// opts in with -force-empty-pass (Basic with an empty password is legitimate on some appliances).
	basic := flag.String("u", "", "HTTP Basic auth 'user:pass' (populates Authorization header)")
	forceEmptyPass := flag.Bool("force-empty-pass", false, "allow -u with an empty password")
	ua := flag.String("ua", "Mozilla/5.0 (compatible; sift/"+version+")", "user agent")
	var hdr headerFlags
	flag.Var(&hdr, "H", "extra request header 'K: V' (repeatable)")
	flag.Parse()
	// Learn whether the operator explicitly set -engine-timeout — flag.Visit lists ONLY the
	// flags that were passed on the CLI, unlike flag.VisitAll. When the operator overrode
	// the default, engineCmdBudget respects that number over feroxBudget/nomoreBudget. When
	// left at the default, the auto-derived per-engine budget wins so common.txt no longer
	// truncates on every target (the round-5 sweep failure mode).
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "engine-timeout" {
			cfg.engineTimeoutSetByUser = true
		}
	})
	// -mode is a lever with three legal positions; any other value is a typo the operator
	// would only notice after a wasted scan. Fail loudly instead of silently running standard.
	switch cfg.Mode {
	case "fast", "standard", "deep":
	default:
		fmt.Fprintf(os.Stderr, "sift: -mode must be fast | standard | deep, got %q\n", cfg.Mode)
		os.Exit(2)
	}
	// -version prints and exits BEFORE -audit and the URL requirement so a packaging script
	// (`sift -version` in a Dockerfile / brew formula) doesn't need to hand the binary a URL
	// just to learn what version it shipped.
	if *versionFlag {
		fmt.Println("sift", version)
		os.Exit(0)
	}
	// -audit runs the integration self-check and exits — no URL needed. This is the answer to
	// "how do I know my install is healthy without waiting for a real scan to fail?"
	if *auditMode {
		os.Exit(runAudit())
	}
	// Allow flags to appear before, between, or after the positional URL (Go's flag package
	// otherwise stops at the first non-flag). Gather all positionals by re-parsing the tail.
	var positional []string
	for rest := flag.Args(); len(rest) > 0; rest = flag.Args() {
		positional = append(positional, rest[0])
		flag.CommandLine.Parse(rest[1:])
	}
	cfg.UA = *ua
	cfg.Throttle = NewThrottle(cfg.Delay)
	if *cookie != "" {
		cfg.Headers["Cookie"] = *cookie
	}
	// HTTP Basic: split on the FIRST colon so passwords containing ":" survive intact
	// (SetBasicAuth's own semantics). An empty password is a real misconfiguration far
	// more often than a legitimate credential, so refuse it unless -force-empty-pass.
	if *basic != "" {
		user, pass, hasColon := strings.Cut(*basic, ":")
		if !hasColon {
			fmt.Fprintln(os.Stderr, "basic: -u expects 'user:pass' (missing ':')")
			os.Exit(1)
		}
		if pass == "" && !*forceEmptyPass {
			fmt.Fprintln(os.Stderr, "basic: -u password is empty (pass -force-empty-pass to allow)")
			os.Exit(1)
		}
		cfg.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		fmt.Printf("[*] auth: HTTP Basic as %q\n", user)
	}
	for _, e := range strings.Split(*exts, ",") {
		if e = strings.TrimSpace(e); e != "" {
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			cfg.Exts = append(cfg.Exts, e)
		}
	}
	for _, h := range hdr {
		if k, v, ok := strings.Cut(h, ":"); ok {
			cfg.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sift [flags] <url>")
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Silent-discard of extra positionals used to hide typos like `sift -w list.txt https://a https://b`
	// where the user thought both URLs would be scanned. Fail loudly instead — sift scans one URL per run.
	if len(positional) > 1 {
		fmt.Fprintf(os.Stderr, "sift scans one target per run; extra positional arguments: %v\n", positional[1:])
		fmt.Fprintln(os.Stderr, "if you meant to scan them all, run sift once per target (or wrap in a shell loop)")
		os.Exit(1)
	}
	raw := positional[0]
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	target, err := url.Parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad url:", err)
		os.Exit(1)
	}
	if target.Path == "" {
		target.Path = "/"
	}
	client, err := newClient(cfg)
	if err != nil {
		// Fatal: with -x invalid, requests would go direct to the origin carrying -b/-H
		// auth. That is exactly the leak -x is meant to prevent, so abort instead of
		// scanning without the operator-requested proxy.
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
	cfg.Wordlist = *wordlist // path handed to the external brute engine (ferox/ffuf)

	// Preventive coverage: at a fixed rate the brute engine needs ~lines/rate seconds; if the
	// engine timeout is smaller it would silently truncate mid-wordlist (and miss late entries
	// like "test1"). Auto-raise it so a full pass is guaranteed unless the user forces otherwise.
	if cfg.Rate > 0 && *wordlist != "" {
		if b, err := os.ReadFile(*wordlist); err == nil {
			lines := strings.Count(string(b), "\n")
			if needed := lines/cfg.Rate*13/10 + 30; lines > 0 && cfg.EngineTimeout < needed {
				fmt.Printf("[*] auto-raising -engine-timeout %d→%ds to cover all %d words at %d req/s\n",
					cfg.EngineTimeout, needed, lines, cfg.Rate)
				cfg.EngineTimeout = needed
			}
		}
	}

	skip := map[string]bool{}
	if *resumeFile != "" {
		s, err := loadBaseline(*resumeFile)
		if err != nil {
			// Fatal: silently rescanning the whole target doubles load/cost and gives no hint why.
			fmt.Fprintln(os.Stderr, "resume:", err)
			os.Exit(1)
		}
		for u := range s {
			skip[u] = true
		}
		fmt.Printf("[*] resume: skipping %d URLs from %s\n", len(skip), *resumeFile)
	}
	// Checkpoint: read any prior jsonl entries so a killed scan picks up mid-run. Findings
	// recovered here are seeded into the scanner AND their URLs are added to skip{} so
	// verify() won't repeat them. New findings this run will be appended to the same file.
	var seededFindings []Finding
	if cfg.CheckpointPath != "" {
		prior, priorSkip, err := loadCheckpoint(cfg.CheckpointPath)
		if err != nil {
			// Fatal for the same reason -resume is fatal on error: a resume that silently
			// starts fresh is a resume that double-scans (and prints "coverage: complete"
			// while missing prior findings from the JSON output).
			fmt.Fprintln(os.Stderr, "checkpoint:", err)
			os.Exit(1)
		}
		for u := range priorSkip {
			skip[u] = true
		}
		seededFindings = prior
		if len(prior) > 0 {
			fmt.Printf("[*] checkpoint: %d prior findings loaded from %s (%d URLs to skip)\n",
				len(prior), cfg.CheckpointPath, len(priorSkip))
		}
	}
	fmt.Printf("[*] target=%s  depth=%d  ext=%v\n", target, cfg.MaxDepth, cfg.Exts)
	scanner := NewScanner(cfg, client, target, skip)
	defer scanner.Close()
	scanner.SeedFindings(seededFindings)
	findings := scanner.Run()
	sort.Slice(findings, func(i, j int) bool { return findings[i].URL < findings[j].URL })

	// HAR export happens BEFORE the JSON output so a failed write is reported next to the
	// findings, not tacked on after. By default a HAR write failure is non-fatal — the JSON
	// findings still land. With -har-required, a CI job that wanted the HAR handoff can gate
	// on the exit code instead of parsing stderr.
	harFailed := false
	if cfg.HAROutput != "" {
		if err := writeHAR(cfg.HAROutput, scanner.HAREntries()); err != nil {
			fmt.Fprintf(os.Stderr, "har: %v\n", err)
			harFailed = true
		} else {
			fmt.Printf("[+] har -> %s\n", cfg.HAROutput)
		}
	}

	// Post-process: optionally drop static assets, then collapse same-response clusters (WAF pages).
	assetCount := 0
	if !cfg.Assets {
		kept := findings[:0]
		for _, f := range findings {
			if f.Kind == "asset" {
				assetCount++
				continue
			}
			kept = append(kept, f)
		}
		findings = kept
	} else {
		for _, f := range findings {
			if f.Kind == "asset" {
				assetCount++
			}
		}
	}
	before := len(findings)
	findings = collapse(findings, cfg.Collapse)
	mergedPaths := before - len(findings)

	newCount, reviewCount, changedCount := 0, 0, 0
	prev := map[string]Finding{}
	if *diffFile != "" {
		p, err := loadBaseline(*diffFile)
		if err != nil {
			// Warn-continue: don't abort a finished scan, but flag that every finding will
			// look "new" against an empty baseline so the reader can't miss the mismatch.
			fmt.Fprintln(os.Stderr, "diff:", err, "(baseline empty; all findings tagged new)")
		}
		prev = p
	}
	for i := range findings {
		if findings[i].Review {
			reviewCount++
		}
		if *diffFile != "" {
			if changed, why := diffAgainstBaseline(findings[i], prev); changed {
				findings[i].New = true
				findings[i].Change = why
				newCount++
				if why != "new-url" {
					changedCount++
				}
			}
		}
	}
	cov := "\x1b[32mcomplete\x1b[0m"
	if cfg.Truncated.Load() {
		cov = "\x1b[31mPARTIAL — an engine hit -engine-timeout; raise it or lower -rate\x1b[0m"
	}
	fmt.Printf("[*] coverage: %s\n", cov)

	hits := len(findings) - reviewCount
	summary := fmt.Sprintf("%d findings (%d review, %d assets)", hits, reviewCount, assetCount)
	if mergedPaths > 0 {
		summary += fmt.Sprintf(", collapsed %d same-response paths", mergedPaths)
	}
	if *diffFile != "" {
		summary += fmt.Sprintf(", %d new since %s", newCount, *diffFile)
		if changedCount > 0 {
			// "new" alone lumps drift in with genuinely new endpoints; call the drift out
			// separately so the reader sees "3 changed since baseline" rather than assuming
			// every NEW-tagged row is a URL that never existed before.
			summary += fmt.Sprintf(" (%d changed)", changedCount)
		}
	}
	fmt.Printf("\n\x1b[32m[+] %s\x1b[0m\n", summary)
	if *diffFile != "" {
		for _, f := range findings {
			if !f.New {
				continue
			}
			// Two tags: NEW for a URL absent from the baseline, CHANGED for a URL that was
			// there but whose Status/Kind/Bypass moved. Both keep the status prefix so the
			// operator sees the current response at a glance.
			tag := "NEW"
			if f.Change != "" && f.Change != "new-url" {
				tag = "CHANGED"
			}
			line := fmt.Sprintf("  \x1b[32;1m%s [%d] %s", tag, f.Status, f.URL)
			if tag == "CHANGED" {
				line += "  \x1b[33m(" + f.Change + ")\x1b[32;1m"
			}
			line += "\x1b[0m"
			fmt.Println(line)
		}
	}
	oFailed := false
	if *outfile != "" {
		// JSON now wraps findings with meta so a CI script can tell whether the run was
		// complete without parsing stderr. Legacy shape (just the array) is available via
		// a top-level "findings" key — one grep away.
		out := struct {
			Meta struct {
				Target        string `json:"target"`
				Coverage      string `json:"coverage"` // "complete" | "partial"
				PartialReason string `json:"partial_reason,omitempty"`
				Findings      int    `json:"findings"`
				Assets        int    `json:"assets"`
				Review        int    `json:"review"`
			} `json:"meta"`
			Findings []Finding `json:"findings"`
		}{Findings: findings}
		out.Meta.Target = target.String()
		out.Meta.Coverage = "complete"
		if cfg.Truncated.Load() {
			out.Meta.Coverage = "partial"
			// partial_reason names which engine(s) truncated so a CI script gating on
			// coverage:partial can distinguish "raise -engine-timeout" (feroxbuster_timeout)
			// from "retry the whole run" (fetch_errors). Empty means truncated=true was set
			// without a reason string — should not happen, but the field stays omitempty.
			cfg.partialMu.Lock()
			out.Meta.PartialReason = cfg.PartialReason
			cfg.partialMu.Unlock()
		}
		out.Meta.Findings = hits
		out.Meta.Assets = assetCount
		out.Meta.Review = reviewCount
		b, _ := json.MarshalIndent(out, "", "  ")
		// 0600: findings carry target URLs + response bodies that leak reconnaissance state.
		// A shared host shouldn't let other users read them.
		if err := os.WriteFile(*outfile, b, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "output:", err)
			oFailed = true
		} else {
			fmt.Printf("[+] json -> %s  (meta.coverage=%s)\n", *outfile, out.Meta.Coverage)
		}
	}
	// -har-required / -o-required make failed writes a fatal exit — CI jobs that gate on the
	// artifact (feeding Burp/ZAP or a downstream diff) can stop the pipeline instead of
	// getting a "clean" scan with no artifact. Default keeps the write best-effort so a
	// stray disk-full doesn't throw away the scan the operator does have.
	if (harFailed && *harRequired) || (oFailed && *oRequired) {
		os.Exit(2)
	}
}
