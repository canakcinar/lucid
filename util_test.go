package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustNewClient wraps newClient for tests that never set cfg.Proxy — the
// error path is unreachable, so surface any surprise as a test failure
// rather than nil-derefing on the returned client.
func mustNewClient(t *testing.T, cfg *Config) *http.Client {
	t.Helper()
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return c
}

func TestDirOf(t *testing.T) {
	cases := map[string]string{
		"http://h/a/b":  "http://h/a/",
		"http://h/a/b/": "http://h/a/",
		"http://h/x":    "http://h/",
		"http://h/":     "http://h/",
	}
	for in, want := range cases {
		if got := dirOf(in); got != want {
			t.Errorf("dirOf(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollapse(t *testing.T) {
	// 6 WAF-403s share one body (sim=0xAAAA); one real page differs; 2 small-cluster dups.
	fs := []Finding{
		{URL: "/a", Status: 403, Sim: 0xAAAA}, {URL: "/b", Status: 403, Sim: 0xAAAA},
		{URL: "/c", Status: 403, Sim: 0xAAAA}, {URL: "/d", Status: 403, Sim: 0xAAAA},
		{URL: "/e", Status: 403, Sim: 0xAAAA}, {URL: "/f", Status: 403, Sim: 0xAAAB}, // 1 bit off -> same cluster
		{URL: "/real", Status: 200, Sim: 0x1234},
		{URL: "/x", Status: 200, Sim: 0x9999}, {URL: "/y", Status: 200, Sim: 0x9999}, // small dup, below minN
	}
	out := collapse(fs, 5)
	var waf *Finding
	real, xy := 0, 0
	for i := range out {
		if out[i].Collapsed > 0 {
			waf = &out[i]
		}
		if out[i].Status == 200 {
			if out[i].URL == "/real" {
				real++
			} else {
				xy++
			}
		}
	}
	if waf == nil || waf.Collapsed != 6 || len(waf.Members) != 6 {
		t.Fatalf("WAF cluster should collapse 6 with members, got %+v", waf)
	}
	if real != 1 {
		t.Errorf("distinct real page must survive, got %d", real)
	}
	if xy != 2 {
		t.Errorf("below-threshold dup must NOT collapse, got %d rows", xy)
	}
}

// Regression: scanner.cleanDir emits one already-clustered Finding per walled directory
// (Sim=0 zero value, Collapsed=N, Members=[all N wall URLs]). Because those all share
// Sim=0, collapse() sweeps them into one meta-cluster. The bug: it appended only each
// member's .URL and set Collapsed=len(cluster), silently destroying every non-representative
// directory's Members list and reporting the cluster size instead of the true path count.
func TestCollapse_PreservesAlreadyClusteredMembers(t *testing.T) {
	fs := []Finding{
		// dir A wall: 100 URLs collapsed to 1 Finding
		{URL: "http://h/a/1", Status: 403, Sim: 0, Collapsed: 100,
			Members: func() []string {
				m := make([]string, 100)
				for i := range m {
					m[i] = fmt.Sprintf("http://h/a/%d", i+1)
				}
				return m
			}()},
		// dir B wall: 50 URLs
		{URL: "http://h/b/1", Status: 403, Sim: 0, Collapsed: 50,
			Members: func() []string {
				m := make([]string, 50)
				for i := range m {
					m[i] = fmt.Sprintf("http://h/b/%d", i+1)
				}
				return m
			}()},
		// dir C wall: 25 URLs
		{URL: "http://h/c/1", Status: 403, Sim: 0, Collapsed: 25,
			Members: func() []string {
				m := make([]string, 25)
				for i := range m {
					m[i] = fmt.Sprintf("http://h/c/%d", i+1)
				}
				return m
			}()},
		// dir D wall: 10 URLs
		{URL: "http://h/d/1", Status: 403, Sim: 0, Collapsed: 10,
			Members: []string{"http://h/d/1", "http://h/d/2", "http://h/d/3", "http://h/d/4", "http://h/d/5",
				"http://h/d/6", "http://h/d/7", "http://h/d/8", "http://h/d/9", "http://h/d/10"}},
		// dir E wall: 15 URLs
		{URL: "http://h/e/1", Status: 403, Sim: 0, Collapsed: 15,
			Members: func() []string {
				m := make([]string, 15)
				for i := range m {
					m[i] = fmt.Sprintf("http://h/e/%d", i+1)
				}
				return m
			}()},
	}
	out := collapse(fs, 5)
	if len(out) != 1 {
		t.Fatalf("expected 5 wall Findings to meta-cluster into 1 row, got %d", len(out))
	}
	want := 100 + 50 + 25 + 10 + 15
	if out[0].Collapsed != want {
		t.Errorf("Collapsed=%d, want %d (real number of walled paths, not cluster size)",
			out[0].Collapsed, want)
	}
	if len(out[0].Members) != want {
		t.Errorf("Members=%d URLs, want %d — non-representative wall URLs must NOT be dropped",
			len(out[0].Members), want)
	}
	// Spot-check that URLs from every source directory survived — the historical bug dropped
	// b/c/d/e entirely and kept only a/1.
	got := map[string]bool{}
	for _, u := range out[0].Members {
		got[u] = true
	}
	for _, u := range []string{"http://h/a/50", "http://h/b/25", "http://h/c/13", "http://h/d/7", "http://h/e/15"} {
		if !got[u] {
			t.Errorf("missing URL %s from merged Members — data loss on collapse", u)
		}
	}
}

// Regression: SimHash("") is defined as the sentinel 0 (see TestSimHashEmpty). Two
// empty-body findings with the SAME status but DIFFERENT redirect Locations (e.g.
// nginx `return 302 /login;` on /admin and `return 302 /error;` on /users) share
// Sim=0 and would Hamming-collide, merging into a single row whose Via reports only
// one of the two Locations. Distinct Vias must produce distinct clusters.
func TestCollapse_EmptyBodyDistinctViasDoNotMerge(t *testing.T) {
	var fs []Finding
	for i := 0; i < 6; i++ {
		fs = append(fs, Finding{
			URL: fmt.Sprintf("http://h/admin/%d", i), Status: 302, Sim: 0,
			Via: "http://h/login",
		})
	}
	for i := 0; i < 6; i++ {
		fs = append(fs, Finding{
			URL: fmt.Sprintf("http://h/users/%d", i), Status: 302, Sim: 0,
			Via: "http://h/error",
		})
	}
	out := collapse(fs, 5)
	if len(out) != 2 {
		t.Fatalf("expected 2 clusters (one per redirect Location), got %d rows", len(out))
	}
	perVia := map[string]int{}
	for _, f := range out {
		perVia[f.Via] = f.Collapsed
	}
	if perVia["http://h/login"] != 6 || perVia["http://h/error"] != 6 {
		t.Fatalf("empty-body findings with distinct Via must stay separate, got %v", perVia)
	}
}

// Regression: a real shell (or a bypassed 401/403, or a URL that fired a secret pattern)
// getting swept into a WAF-wall aggregate must NOT lose those signals — the aggregate row
// is supposed to compress noise, not hide leads. The old collapse used `rep := fs[i]` and
// then only carried Note across members; Kind, Bypass, Secrets on non-representative
// cluster members were silently dropped.
func TestCollapse_PromotesDistinguishingMemberData(t *testing.T) {
	fs := []Finding{
		{URL: "http://h/a", Status: 403, Sim: 0xAAAA},
		{URL: "http://h/b", Status: 403, Sim: 0xAAAA, Kind: "shell"},
		{URL: "http://h/c", Status: 403, Sim: 0xAAAA, Bypass: "unverified:mid-path"},
		{URL: "http://h/d", Status: 403, Sim: 0xAAAA, Secrets: []string{"aws-akid"}},
		{URL: "http://h/e", Status: 403, Sim: 0xAAAA, Secrets: []string{"aws-akid", "generic-secret"}},
	}
	out := collapse(fs, 5)
	if len(out) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(out))
	}
	rep := out[0]
	if rep.Kind != "shell" {
		t.Errorf("shell Kind must be promoted to the representative, got %q", rep.Kind)
	}
	if rep.Bypass != "unverified:mid-path" {
		t.Errorf("Bypass must survive onto the representative, got %q", rep.Bypass)
	}
	// Union of member Secrets, deduplicated.
	got := map[string]int{}
	for _, s := range rep.Secrets {
		got[s]++
	}
	if got["aws-akid"] != 1 || got["generic-secret"] != 1 || len(rep.Secrets) != 2 {
		t.Errorf("Secrets must union+dedupe across members, got %v", rep.Secrets)
	}
}

func TestWallOf(t *testing.T) {
	if st, w := wallOf(Profile{Statuses: map[int]bool{403: true}}); !w || st != 403 {
		t.Errorf("static 403 should be a wall, got st=%d w=%v", st, w)
	}
	if _, w := wallOf(Profile{Statuses: map[int]bool{200: true}}); w {
		t.Error("200 baseline is not a wall")
	}
	if _, w := wallOf(Profile{Statuses: map[int]bool{403: true}, Dynamic: true}); w {
		t.Error("dynamic 403 must not be treated as a uniform wall")
	}
	if _, w := wallOf(Profile{Statuses: map[int]bool{403: true, 200: true}}); w {
		t.Error("mixed statuses are not a wall")
	}
}

func TestIsSensitive(t *testing.T) {
	sens := []string{
		"http://h/.git/config", "http://h/.env", "http://h/actuator/env",
		"http://h/actuator/heapdump", "http://h/api/actuator", "http://h/wp-config.php",
		"http://h/backup.zip", "http://h/.aws/credentials", "http://h/swagger/",
	}
	for _, u := range sens {
		if !isSensitive(u) {
			t.Errorf("must be sensitive: %s", u)
		}
	}
	safe := []string{"http://h/config.json", "http://h/api/v1/users", "http://h/login"}
	for _, u := range safe {
		if isSensitive(u) {
			t.Errorf("must NOT be sensitive: %s", u)
		}
	}
}

func TestLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Wrapped shape with findings. Baseline stores per-URL Findings, so also verify the
	// stored Status/Kind/Bypass make it through — the -diff comparison depends on them.
	set, err := loadBaseline(write("wrapped.json", `{"meta":{},"findings":[{"url":"http://h/a","status":200,"kind":"shell"},{"url":"http://h/b","status":403,"bypass":"case-swap"}]}`))
	_, hasA := set["http://h/a"]
	_, hasB := set["http://h/b"]
	if err != nil || len(set) != 2 || !hasA || !hasB {
		t.Errorf("wrapped: got set=%v err=%v", set, err)
	}
	if set["http://h/a"].Status != 200 || set["http://h/a"].Kind != "shell" {
		t.Errorf("wrapped: /a metadata not preserved: %+v", set["http://h/a"])
	}
	if set["http://h/b"].Status != 403 || set["http://h/b"].Bypass != "case-swap" {
		t.Errorf("wrapped: /b metadata not preserved: %+v", set["http://h/b"])
	}

	// Wrapped shape, empty findings: legitimate 0-finding run, must not error.
	set, err = loadBaseline(write("wrapped_empty.json", `{"meta":{},"findings":[]}`))
	if err != nil || len(set) != 0 {
		t.Errorf("wrapped-empty: got set=%v err=%v (want empty, nil)", set, err)
	}

	// Bare-array shape (older schema).
	set, err = loadBaseline(write("array.json", `[{"url":"http://h/x","status":301}]`))
	_, hasX := set["http://h/x"]
	if err != nil || len(set) != 1 || !hasX {
		t.Errorf("array: got set=%v err=%v", set, err)
	}
	if set["http://h/x"].Status != 301 {
		t.Errorf("array: /x status not preserved: %+v", set["http://h/x"])
	}

	// Truncated / invalid JSON — must return an error, not a silent empty set.
	if _, err := loadBaseline(write("truncated.json", `{"findings":[{"url":"http://h/a"}`)); err == nil {
		t.Error("truncated JSON must return an error")
	}

	// Wrong-shape JSON (object with no findings key, not an array).
	if _, err := loadBaseline(write("wrong.json", `{"other":"thing"}`)); err == nil {
		t.Error("object without findings key must return an error")
	}

	// Missing file: os error propagates.
	if _, err := loadBaseline(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("missing file must return an error")
	}
}

// TestDiffAgainstBaseline_DetectsStatusKindBypassDrift — regression for the -diff
// flag's original blind spot: comparing only URL presence hid every meaningful
// regression on a URL that was already in the baseline (200→403, shell demoted to
// asset, freshly-working nomore403 bypass). Each drift kind here corresponds to a
// real monitoring signal that used to disappear silently.
func TestDiffAgainstBaseline_DetectsStatusKindBypassDrift(t *testing.T) {
	base := map[string]Finding{
		"http://h/admin":     {URL: "http://h/admin", Status: 200, Kind: "shell"},
		"http://h/asset.js":  {URL: "http://h/asset.js", Status: 200, Kind: "asset"},
		"http://h/blocked":   {URL: "http://h/blocked", Status: 403},
		"http://h/bypassed":  {URL: "http://h/bypassed", Status: 403, Bypass: "case-swap"},
		"http://h/unchanged": {URL: "http://h/unchanged", Status: 200, Kind: "shell"},
	}

	cases := []struct {
		name   string
		cur    Finding
		want   bool
		reason string
	}{
		{"new-url flagged", Finding{URL: "http://h/brand-new", Status: 200}, true, "new-url"},
		{"status flip 200->403 flagged", Finding{URL: "http://h/admin", Status: 403, Kind: "shell"}, true, "status:200->403"},
		{"kind demoted shell->asset flagged", Finding{URL: "http://h/admin", Status: 200, Kind: "asset"}, true, `kind:"shell"->"asset"`},
		{"bypass gained flagged", Finding{URL: "http://h/blocked", Status: 403, Bypass: "path-fuzz"}, true, "bypass-added"},
		{"bypass lost flagged", Finding{URL: "http://h/bypassed", Status: 403}, true, "bypass-removed"},
		{"identical is not new", Finding{URL: "http://h/unchanged", Status: 200, Kind: "shell"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, why := diffAgainstBaseline(tc.cur, base)
			if changed != tc.want || why != tc.reason {
				t.Errorf("diffAgainstBaseline=%v,%q want %v,%q", changed, why, tc.want, tc.reason)
			}
		})
	}
}

// TestGraftPort_GauResultsSurviveNormOnNonDefaultPort — regression for a silent coverage
// hole: runGau received the target's Hostname() (port stripped), and Wayback normalizes
// archive URLs to the default port, so a target on https://example.com:8443/ had every
// gau URL come back as https://example.com/... and get discarded by norm() (Host mismatch).
// The archive engine still printed gau(N) in the summary while contributing zero candidates.
// After the fix, graftPort() rewrites the returned URL's Host to include the target's port
// before norm() sees it — the URL must then survive as an on-scope, ported candidate.
func TestGraftPort_GauResultsSurviveNormOnNonDefaultPort(t *testing.T) {
	target, _ := url.Parse("https://example.com:8443/")

	// Wayback/gau-shaped inputs: same hostname, no explicit port (scheme default).
	gauShaped := []string{
		"https://example.com/admin",
		"https://example.com/api/v1/users?id=1",
		"http://example.com/legacy", // scheme drift is realistic; port still grafted
	}
	for _, raw := range gauShaped {
		g := graftPort(target, raw)
		n := norm(target, g)
		if n == "" {
			t.Errorf("gau URL %q was dropped after graftPort — non-default-port coverage lost", raw)
			continue
		}
		u, err := url.Parse(n)
		if err != nil {
			t.Fatalf("norm returned unparseable %q: %v", n, err)
		}
		if u.Host != target.Host {
			t.Errorf("normalized Host=%q want %q (port must be preserved)", u.Host, target.Host)
		}
	}

	// Off-host URL must NOT be rewritten just because it lacks a port — graftPort only
	// helps when the hostname already matches.
	if got := graftPort(target, "https://other.com/x"); got != "https://other.com/x" {
		t.Errorf("off-host URL must not be rewritten, got %q", got)
	}
	if n := norm(target, graftPort(target, "https://other.com/x")); n != "" {
		t.Errorf("off-host URL must still be rejected by norm, got %q", n)
	}

	// A URL that already carries a DIFFERENT explicit port names a different host in
	// norm()'s sense and must not be silently rewritten to match the target.
	if got := graftPort(target, "https://example.com:9000/admin"); got != "https://example.com:9000/admin" {
		t.Errorf("URL with different explicit port must not be rewritten, got %q", got)
	}

	// Same explicit port is a no-op (idempotent).
	if got := graftPort(target, "https://example.com:8443/admin"); got != "https://example.com:8443/admin" {
		t.Errorf("URL that already carries the target's port must be unchanged, got %q", got)
	}

	// Default-port target: graftPort is a no-op — the old codepath is preserved.
	def, _ := url.Parse("https://example.com/")
	if got := graftPort(def, "https://example.com/x"); got != "https://example.com/x" {
		t.Errorf("default-port target must leave URLs untouched, got %q", got)
	}
}

func TestScanSecrets(t *testing.T) {
	body := `{"aws_key":"AKIA1234567890ABCDEF","client_secret":"abcdefghijklmnopqr123","api_key":"xyz"}`
	hits := scanSecrets(body, "application/json")
	found := map[string]bool{}
	for _, h := range hits {
		found[h] = true
	}
	if !found["aws-akid"] {
		t.Errorf("aws-akid must fire, got %v", hits)
	}
	if !found["generic-secret"] {
		t.Errorf("generic-secret must fire, got %v", hits)
	}
	// binary content-type must be skipped
	if got := scanSecrets("AKIA1234567890ABCDEF", "application/octet-stream"); got != nil {
		t.Errorf("binary must not be scanned, got %v", got)
	}
}

// TestDecoyFor_CoversSensitivePathVariants — decoyFor is the backbone of WAF-pattern-block
// detection. Every sensitive path shape must produce a decoy under the SAME directory whose
// LAST segment carries the original trigger (so a name-based WAF regex still fires) plus a
// random tail (so no real file exists there). Documented shapes: dotfiles (.env), dotfile
// variants (.env.production, .env.local), version-control (.git), and nested (actuator/env).
func TestDecoyFor_CoversSensitivePathVariants(t *testing.T) {
	cases := []string{
		"http://h/.env", "http://h/.env.production", "http://h/.env.local",
		"http://h/.git", "http://h/actuator/env", "http://h/wp-config.php",
	}
	for _, u := range cases {
		d := decoyFor(u)
		if d == "" {
			t.Errorf("decoyFor(%q) returned empty — pattern would be probed as real, not as name-block", u)
			continue
		}
		if d == u {
			t.Errorf("decoyFor(%q) returned the same path — WAF would fire same rule and we can't distinguish", u)
		}
		// Decoy must sit in the SAME directory (nomore than one path segment differs).
		lastSlashOrig := strings.LastIndex(u, "/")
		lastSlashDec := strings.LastIndex(d, "/")
		if u[:lastSlashOrig+1] != d[:lastSlashDec+1] {
			t.Errorf("decoyFor(%q)=%q moved the decoy to a different directory", u, d)
		}
		// Decoy filename must START with the original last segment (so a name-based WAF
		// rule triggered by "env" or ".env" still matches).
		origLast := u[lastSlashOrig+1:]
		decLast := d[lastSlashDec+1:]
		if !strings.HasPrefix(decLast, origLast) {
			t.Errorf("decoyFor(%q)=%q dropped the trigger prefix %q — WAF wouldn't be tested for the same rule", u, d, origLast)
		}
		// And it must have a random tail so a real file with THIS name can't exist.
		if decLast == origLast {
			t.Errorf("decoyFor(%q) returned the trigger unchanged — a real file would collide", u)
		}
	}
}
