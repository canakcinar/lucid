package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// A hostile target can publish `Sitemap: https://evil/log` in its robots.txt; without a scope
// guard, lucid fetches that URL with the operator's -b cookie and -H auth headers still attached.
// This test stands up a target server whose robots.txt points sitemap at a second server on a
// different host and asserts the second server never receives a request from passivePaths.
func TestPassivePaths_OffScopeSitemapRefNotFetched(t *testing.T) {
	var evilHits int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&evilHits, 1)
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>/exfil</loc></url></urlset>`)
	}))
	defer evil.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "User-agent: *\nDisallow: /admin\nSitemap: %s/sitemap.xml\n", evil.URL)
		case "/sitemap.xml":
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	defer target.Close()

	u, _ := url.Parse(target.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test", Headers: map[string]string{"Cookie": "session=secret"}}
	_ = passivePaths(mustNewClient(t, cfg), u, cfg)

	if n := atomic.LoadInt64(&evilHits); n != 0 {
		t.Fatalf("off-scope Sitemap: URL was fetched %d time(s) — auth headers would have leaked", n)
	}
}

// Defense in depth: fetchSitemap must refuse a cross-host URL even if a caller forgets to guard.
func TestFetchSitemap_RefusesCrossHost(t *testing.T) {
	var hits int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>/x</loc></url></urlset>`)
	}))
	defer evil.Close()

	target, _ := url.Parse("http://lucid-target.invalid/")
	cfg := &Config{Timeout: 2, UA: "lucid-test"}
	if got := fetchSitemap(mustNewClient(t, cfg), target, evil.URL+"/sitemap.xml", cfg); got != nil {
		t.Fatalf("fetchSitemap returned %v for a cross-host URL", got)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("cross-host sitemap was fetched %d time(s)", n)
	}
}

// TestOpenAPIPaths_SwaggerV2BasePath — swagger.json is a literal endpoint catalog. When the
// server publishes /v2/api-docs with basePath="/api", the expansion must prefix every path in
// `paths` with basePath so ferox's wordlist stops being the only source of API coverage.
func TestOpenAPIPaths_SwaggerV2BasePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/api-docs" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"swagger":"2.0","basePath":"/api","paths":{"/users":{"get":{}},"/orders/{id}":{"get":{}}}}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test", MaxCandidates: 20000}
	out := openapiPaths(mustNewClient(t, cfg), u, cfg)

	want := map[string]bool{
		srv.URL + "/api/users":       false,
		srv.URL + "/api/orders/{id}": false,
	}
	for _, p := range out {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, got := range want {
		if !got {
			t.Fatalf("expected %q in output, got %v", p, out)
		}
	}
}

// TestOpenAPIPaths_OpenAPIV3ServersSameHost — v3 puts the prefix in servers[].url. We must take
// the first same-host server (a partner API in another server entry must not redirect our fetches
// off-scope, which would leak -b / -H auth headers).
func TestOpenAPIPaths_OpenAPIV3ServersSameHost(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			// First server is off-host (partner API) — must be skipped. Second is same-host with a
			// /v3 prefix that the expanded URLs must carry.
			body := fmt.Sprintf(`{
				"openapi":"3.0.0",
				"servers":[{"url":"https://partner.example/api"},{"url":"%s/v3"}],
				"paths":{"/health":{},"/users/me":{}}
			}`, srv.URL)
			fmt.Fprint(w, body)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test", MaxCandidates: 20000}
	out := openapiPaths(mustNewClient(t, cfg), u, cfg)

	wantHealth := srv.URL + "/v3/health"
	wantMe := srv.URL + "/v3/users/me"
	var haveHealth, haveMe bool
	for _, p := range out {
		if p == wantHealth {
			haveHealth = true
		}
		if p == wantMe {
			haveMe = true
		}
		if strings.HasPrefix(p, "https://partner.example") {
			t.Fatalf("off-host server URL leaked into output: %q", p)
		}
	}
	if !haveHealth || !haveMe {
		t.Fatalf("expected %q and %q in output, got %v", wantHealth, wantMe, out)
	}
}

// TestOpenAPIPaths_RespectsMaxCandidates — a pathological doc with tens of thousands of paths
// must not blow past the operator's -max-candidates cap; the doc is untrusted input.
func TestOpenAPIPaths_RespectsMaxCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			var b strings.Builder
			b.WriteString(`{"openapi":"3.0.0","paths":{`)
			for i := 0; i < 500; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `"/p%d":{}`, i)
			}
			b.WriteString(`}}`)
			fmt.Fprint(w, b.String())
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test", MaxCandidates: 10}
	out := openapiPaths(mustNewClient(t, cfg), u, cfg)
	if len(out) > 10 {
		t.Fatalf("openapiPaths returned %d results, cap was 10", len(out))
	}
}

// TestOpenAPIPaths_IgnoresNon200 — an HTML 200 "not found" or a text/html body must not be
// misparsed. Same for non-JSON Content-Type.
func TestOpenAPIPaths_IgnoresNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>{"paths":{"/oops":{}}}</body></html>`)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test", MaxCandidates: 20000}
	if out := openapiPaths(mustNewClient(t, cfg), u, cfg); len(out) != 0 {
		t.Fatalf("expected empty output on text/html, got %v", out)
	}
}

// A legitimate same-host Sitemap: entry must still be honored — the fix must not break the
// normal case that passive discovery is here for.
func TestPassivePaths_SameHostSitemapStillFetched(t *testing.T) {
	var sitemapHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "User-agent: *\nSitemap: http://%s/sitemap.xml\n", r.Host)
		case "/sitemap.xml":
			atomic.AddInt64(&sitemapHits, 1)
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>http://%s/api/hidden</loc></url></urlset>`, r.Host)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 2, UA: "lucid-test"}
	out := passivePaths(mustNewClient(t, cfg), u, cfg)

	if atomic.LoadInt64(&sitemapHits) == 0 {
		t.Fatal("on-scope sitemap was not fetched — fix over-blocked legitimate case")
	}
	var seen bool
	for _, p := range out {
		if p == fmt.Sprintf("http://%s/api/hidden", u.Host) {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatalf("expected sitemap <loc> in output, got %v", out)
	}
}
