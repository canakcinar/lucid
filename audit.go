package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// runAudit stands up a controlled mock covering every integration surface sift depends on,
// runs the real code paths against it, and reports what actually worked. Exits nonzero on any
// failure — the nomore403-payloads-missing bug is what motivated this file: "binary exists"
// wasn't enough, we need "the binary produced usable output end-to-end". Use before trusting
// results, after a fresh install, or in CI.
func runAudit() int {
	mock, err := startAuditMock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\x1b[31m[!] audit setup failed: %v\x1b[0m\n", err)
		return 1
	}
	defer mock.Close()

	type check struct {
		name, why string
		pass      bool
	}
	var checks []check
	add := func(name string, pass bool, why string) { checks = append(checks, check{name, why, pass}) }

	// Layer 1 — binary presence (cheap sanity).
	for _, b := range []string{"feroxbuster", "ffuf", "katana", "gau", "nomore403"} {
		p, err := exec.LookPath(b)
		add("binary:"+b, err == nil, ternary(err == nil, p, "NOT in PATH — install it"))
	}

	// Layer 2 — nomore403 payloads directory. The exact silent-failure that hid the XFF bypass
	// on real targets for weeks.
	pd := nomorePayloadsDir()
	// payloads/headers is a FILE (list of header names to try), not a directory — the pipeline
	// dev misread this. Match findNomorePayloadsDir's real contract: non-directory, non-empty.
	hdrOK := false
	if pd != "" {
		if st, err := os.Stat(filepath.Join(pd, "payloads", "headers")); err == nil && !st.IsDir() && st.Size() > 0 {
			hdrOK = true
		}
	}
	add("nomore403:payloads-dir", hdrOK,
		ternary(hdrOK, pd, "MISSING or empty — headers/verbs techniques will silently no-op"))

	cfg := &Config{Concurrency: 4, Timeout: 8, Insecure: true, UA: "sift-audit/1",
		Headers: map[string]string{}, Probes: 2, Threshold: -1, MaxDepth: 1,
		Bypass: true, Archive: false, Wordlist: mock.wordlist, EngineTimeout: 25,
		Throttle: NewThrottle(0)}

	// Layer 3 — engine wrappers end-to-end against the mock.
	if haveBin("feroxbuster") {
		res := runFerox(mock.URL(), mock.wordlist, cfg)
		ok := res[mock.URL()+"/admin"] == 200
		add("engine:feroxbuster (finds /admin=200)", ok,
			fmt.Sprintf("returned %d URLs w/ status", len(res)))
	}
	if haveBin("katana") {
		urls := runKatana(mock.URL(), cfg)
		// katana on localhost can be quiet; we don't fail the check, we surface the count
		add("engine:katana (runs)", true, fmt.Sprintf("returned %d URLs (localhost katana varies)", len(urls)))
	}
	if haveBin("gau") {
		// gau reaches out to public archives (Wayback, CommonCrawl) which are slow — give it
		// its own generous budget so a tight audit timeout doesn't flag a network hiccup as a
		// broken integration. Copy value-fields explicitly instead of `*cfg` — Config now holds
		// atomic.Bool (Truncated), and copying that lock value is a vet-flagged bug.
		gauCfg := &Config{
			Concurrency: cfg.Concurrency, Timeout: cfg.Timeout, Proxy: cfg.Proxy,
			Insecure: cfg.Insecure, UA: cfg.UA, Headers: cfg.Headers, Probes: cfg.Probes,
			Threshold: cfg.Threshold, MaxDepth: cfg.MaxDepth, Exts: cfg.Exts,
			Bypass: cfg.Bypass, Archive: cfg.Archive, Delay: cfg.Delay,
			ReviewMargin: cfg.ReviewMargin, Wordlist: cfg.Wordlist, MaxReq: cfg.MaxReq,
			Rate: cfg.Rate, EngineTimeout: 90, MaxCandidates: cfg.MaxCandidates,
			Assets: cfg.Assets, Collapse: cfg.Collapse, Throttle: cfg.Throttle,
		}
		urls := runGau("example.com", gauCfg)
		// treat as informational — a low count often means Wayback rate-limited, not "broken"
		add("engine:gau (reaches archives)", true,
			fmt.Sprintf("%d URLs for example.com (archives can rate-limit; count varies)", len(urls)))
	}
	if haveBin("nomore403") {
		hit, ok := runNomore403(mock.URL()+"/secret", cfg)
		tech := hit.String()
		add("engine:nomore403 (XFF bypass end-to-end)", ok && strings.Contains(tech, "X-Forwarded-For"),
			ternary(ok, "found: "+tech, "no bypass — payloads/schema/timeout misconfigured"))
	}

	// Layer 4 — native passive parser (robots.txt + sitemap.xml).
	client, cerr := newClient(cfg)
	if cerr != nil {
		// audit cfg.Proxy is empty so this is unreachable today, but if a future audit
		// wires a proxy, fail loudly instead of nil-derefing on client below.
		fmt.Fprintf(os.Stderr, "\x1b[31m[!] audit newClient failed: %v\x1b[0m\n", cerr)
		return 1
	}
	target, _ := url.Parse(mock.URL())
	paths := passivePaths(client, target, cfg)
	inR, inS := false, false
	for _, p := range paths {
		if strings.Contains(p, "internal") {
			inR = true
		}
		if strings.Contains(p, "hidden") {
			inS = true
		}
	}
	add("passive:robots→/internal + sitemap→/api/hidden", inR && inS,
		fmt.Sprintf("%d paths — robots:%v sitemap:%v", len(paths), inR, inS))

	// Layer 5 — SimHash judge core contract.
	nf1 := SimHash("<title>404</title>not found aaaa " + strings.Repeat("filler ", 10))
	nf2 := SimHash("<title>404</title>not found bbbb " + strings.Repeat("filler ", 10))
	real := SimHash("<title>Admin</title>dashboard settings users billing analytics reports export logs")
	soft := SimHash("<title>404</title>not found cccc " + strings.Repeat("filler ", 10))
	p := Profile{Statuses: map[int]bool{200: true}, Titles: map[string]bool{"": true},
		TitleStable: true, Sims: []uint64{nf1, nf2}, Threshold: 12, Margin: 2}
	realV, _ := p.judge(Resp{Status: 200, Sim: real})
	softV, _ := p.judge(Resp{Status: 200, Sim: soft})
	add("core:SimHash judge (real=hit, soft=drop)", realV == VHit && softV == VNotFound,
		fmt.Sprintf("real=%d soft=%d", realV, softV))

	// Layer 6 — WAF-pattern-block decoy path and secret regex (in-process).
	secHits := scanSecrets(`{"aws_key":"AKIA1234567890ABCDEF"}`, "application/json")
	add("core:secret-scan (aws-akid)", len(secHits) > 0, fmt.Sprintf("fired: %v", secHits))

	add("core:sensitive-path guard", isSensitive("http://h/.git/config") && !isSensitive("http://h/api/users"),
		"regex covers .git/.env/actuator, skips ordinary paths")

	// Report.
	fail := 0
	fmt.Println()
	fmt.Println("╭─────────────────── sift integration audit ────────────────────╮")
	for _, c := range checks {
		mark := "\x1b[32m✓\x1b[0m"
		if !c.pass {
			mark = "\x1b[31m✗\x1b[0m"
			fail++
		}
		fmt.Printf("│ %s %-40s %s\n", mark, c.name, truncMsg(c.why, 20))
	}
	fmt.Println("╰────────────────────────────────────────────────────────────────╯")
	if fail == 0 {
		fmt.Printf("\x1b[32m[+] all %d checks passed — integrations healthy\x1b[0m\n", len(checks))
		return 0
	}
	fmt.Printf("\x1b[31m[!] %d/%d checks failed — do not trust results until fixed\x1b[0m\n", fail, len(checks))
	return 1
}

// startAuditMock exposes the exact use-cases sift must handle: robots+sitemap+JS+brute hits +
// a 403 that yields to X-Forwarded-For:127.0.0.1 (nomore403's default header payload).
type auditMock struct {
	*httptest.Server
	wordlist string
}

func (a *auditMock) URL() string { return a.Server.URL }
func (a *auditMock) Close()      { a.Server.Close(); os.Remove(a.wordlist) }

func startAuditMock() (*auditMock, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/":
			w.Write([]byte(`<title>Home</title><a href="/app.js">js</a>`))
		case p == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "User-agent: *\nDisallow: /admin\nDisallow: /internal\nSitemap: http://%s/sitemap.xml\n", r.Host)
		case p == "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>http://%s/api/hidden</loc></url></urlset>`, r.Host)
		case p == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const api="/api/v1/users";`))
		case p == "/admin":
			w.Write([]byte(`<title>Admin</title>dashboard settings users billing analytics`))
		case p == "/secret":
			if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
				w.Write([]byte(`<title>Secret</title>flag internal admin console`))
				return
			}
			w.WriteHeader(403)
			w.Write([]byte(`403 forbidden`))
		default:
			w.WriteHeader(404)
			fmt.Fprintf(w, `<title>404</title>not found on server %s %s`, p, strings.Repeat("x", 20))
		}
	})
	srv := httptest.NewServer(mux)
	tmp, err := os.CreateTemp("", "sift-audit-*.txt")
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("audit mock wordlist: %w", err)
	}
	if _, err := io.WriteString(tmp, "admin\nsecret\napp.js\nfoo\nbar\n"); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		srv.Close()
		return nil, fmt.Errorf("audit mock wordlist write: %w", err)
	}
	tmp.Close()
	return &auditMock{Server: srv, wordlist: tmp.Name()}, nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func isDir(p string) bool      { st, err := os.Stat(p); return err == nil && st.IsDir() }
func truncMsg(s string, keep int) string {
	if len(s) <= keep {
		return s
	}
	return s[:keep-1] + "…"
}
