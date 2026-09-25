package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Native passive discovery — katana's -kf all is unreliable on localhost/small sites and
// sometimes silently returns nothing even when robots.txt/sitemap.xml exist. We parse them
// ourselves as a backstop; it's ~15 lines of regex and the risk of missing high-signal seeds
// (Disallow paths, sitemap URLs) is not worth the "leave it to katana" purity.

var (
	reDisallow   = regexp.MustCompile(`(?im)^\s*(?:dis)?allow\s*:\s*(\S+)`)
	reSitemapRef = regexp.MustCompile(`(?im)^\s*sitemap\s*:\s*(\S+)`)
	reSitemapLoc = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
)

// sameHost keeps sitemap/robots-referenced fetches on-scope. A hostile target can publish
// `Sitemap: https://evil/log` and steal the operator's -b cookie / -H auth headers otherwise.
// Comparing u.Host (host:port) not u.Hostname() — two servers on 127.0.0.1 with different
// ports are different scopes; treating them as one would defeat the guard on localhost tests.
func sameHost(target *url.URL, raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "" && u.Scheme != target.Scheme {
		return false
	}
	return strings.EqualFold(u.Host, target.Host)
}

func passivePaths(client *http.Client, target *url.URL, cfg *Config) []string {
	root := target.Scheme + "://" + target.Host
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	rb := fetch(client, target, root+"/robots.txt", cfg)
	if rb.Err == nil && rb.Status == 200 {
		for _, m := range reDisallow.FindAllStringSubmatch(rb.Body, -1) {
			add(m[1])
		}
		for _, m := range reSitemapRef.FindAllStringSubmatch(rb.Body, -1) {
			// Off-scope Sitemap: entries would leak -b cookies / -H auth to an attacker host.
			if !sameHost(target, m[1]) {
				fmt.Fprintf(os.Stderr, "\x1b[33m[!] robots.txt Sitemap: %s is off-scope — dropped (would leak auth)\x1b[0m\n", m[1])
				continue
			}
			for _, u := range fetchSitemap(client, target, m[1], cfg) {
				add(u)
			}
		}
	}
	for _, u := range fetchSitemap(client, target, root+"/sitemap.xml", cfg) {
		add(u)
	}
	// .well-known — RFC-defined discovery paths (security.txt is high-signal on real programs)
	for _, wk := range []string{"/.well-known/security.txt", "/.well-known/openid-configuration"} {
		r := fetch(client, target, root+wk, cfg)
		if r.Err == nil && r.Status == 200 {
			add(wk)
		}
	}
	return out
}

// openapiPaths probes a fixed set of well-known Swagger/OpenAPI document locations. When one
// returns 200 + JSON, we parse it and expand every entry in the `paths` object into a candidate
// URL — swagger.json is a literal catalog of every endpoint on API targets, and leaving it as a
// single sensitive-file finding while ferox brute-forces a wordlist is the single biggest missed
// multiplier this tool had. Tagged with source "openapi" so the coverage line credits it apart
// from robots.txt/sitemap.xml (which stay under "passive").
//
// v2 (Swagger): paths are relative to top-level `basePath` (e.g. "/api").
// v3 (OpenAPI): paths are relative to the first `servers[].url` that resolves to the same host —
// off-host servers are ignored so we never send the operator's -b cookie / -H auth headers to a
// third-party API that the doc happened to reference.
func openapiPaths(client *http.Client, target *url.URL, cfg *Config) []string {
	root := target.Scheme + "://" + target.Host
	probes := []string{
		"/swagger.json",
		"/v2/api-docs",
		"/v3/api-docs",
		"/openapi.json",
		"/openapi.yaml",
		"/swagger/v1/swagger.json",
	}
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		if cfg.MaxCandidates > 0 && len(out) >= cfg.MaxCandidates {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	for _, probe := range probes {
		r := fetch(client, target, root+probe, cfg)
		if r.Err != nil || r.Status != 200 {
			continue
		}
		// openapi.yaml is a valid probe target but we only parse JSON here — YAML would drag in
		// a third-party parser for a document we can already discover as a sensitive finding.
		if !strings.Contains(strings.ToLower(r.CType), "json") {
			continue
		}
		var doc struct {
			BasePath string `json:"basePath"` // Swagger v2
			Servers  []struct {
				URL string `json:"url"`
			} `json:"servers"` // OpenAPI v3
			Paths map[string]any `json:"paths"`
		}
		if err := json.Unmarshal([]byte(r.Body), &doc); err != nil {
			continue
		}
		if len(doc.Paths) == 0 {
			continue
		}
		prefix := resolveOpenAPIPrefix(target, doc.BasePath, extractServerURLs(doc.Servers))
		for p := range doc.Paths {
			if p == "" {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			add(root + prefix + p)
			if cfg.MaxCandidates > 0 && len(out) >= cfg.MaxCandidates {
				return out
			}
		}
	}
	return out
}

// extractServerURLs pulls just the URL strings out of the anonymous struct slice so
// resolveOpenAPIPrefix can stay decoupled from the JSON schema shape.
func extractServerURLs(servers []struct {
	URL string `json:"url"`
}) []string {
	if len(servers) == 0 {
		return nil
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.URL)
	}
	return out
}

// resolveOpenAPIPrefix picks the URL prefix that per-endpoint paths sit under. v2 wins if
// basePath is set (Swagger's own rule); otherwise we take the first server URL that either is
// relative (path-only, no host) or absolute and resolves to the target host. Off-host servers
// are ignored so a doc that references a partner API cannot redirect our fetches off-scope.
func resolveOpenAPIPrefix(target *url.URL, basePath string, servers []string) string {
	if bp := strings.TrimRight(basePath, "/"); bp != "" {
		return bp
	}
	for _, raw := range servers {
		su, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if su.Host == "" {
			return strings.TrimRight(su.Path, "/")
		}
		if strings.EqualFold(su.Host, target.Host) {
			return strings.TrimRight(su.Path, "/")
		}
	}
	return ""
}

func fetchSitemap(client *http.Client, target *url.URL, u string, cfg *Config) []string {
	// Defense in depth: refuse cross-host fetches even if a caller forgets to guard.
	if !sameHost(target, u) {
		return nil
	}
	r := fetch(client, target, u, cfg)
	if r.Err != nil || r.Status != 200 || !strings.Contains(strings.ToLower(r.CType), "xml") {
		return nil
	}
	var out []string
	for _, m := range reSitemapLoc.FindAllStringSubmatch(r.Body, -1) {
		out = append(out, m[1])
	}
	return out
}
