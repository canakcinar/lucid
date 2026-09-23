package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestVerifyBypass_HeadersConfirmed — the whole point of the change: a nomore403 header
// hit whose replay lands OUTSIDE the not-found envelope must be labeled "verified:*" and
// carry a BypassPreview snippet. Before the fix every hit was "unverified:*" with no
// preview, so an operator couldn't tell a real bypass from a login page happy-path.
func TestVerifyBypass_HeadersConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>Admin Console</title></head><body>Users, billing, exports</body></html>"))
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte("<html><title>Forbidden</title>forbidden by policy</html>"))
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 5, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)

	// Profile that fingerprints the 403 wall — a differing 200 with a distinct SimHash
	// must escape it.
	wall := fetch(client, target, srv.URL+"/secret", cfg)
	if wall.Status != 403 {
		t.Fatalf("setup: expected wall 403, got %d", wall.Status)
	}
	p := Profile{
		Statuses:  map[int]bool{403: true},
		Sims:      []uint64{wall.Sim},
		Threshold: 4,
	}

	hit := &NomoreHit{Technique: "headers", Payload: "X-Forwarded-For: 127.0.0.1", Status: 200, Length: 88}
	label, preview := verifyBypass(client, target, srv.URL+"/secret", hit, p, cfg, hit.String())
	if !strings.HasPrefix(label, "verified:") {
		t.Fatalf("expected verified label, got %q", label)
	}
	if !strings.Contains(preview, "Admin Console") {
		t.Fatalf("preview must include the winning title, got %q", preview)
	}
}

// TestVerifyBypass_HeadersReplayStillWall — nomore403 said 200 but our replay hits the
// same 403 wall (rate limit, sticky session, ephemeral WAF decision). We must NOT stamp
// "verified" on a hit we couldn't reproduce.
func TestVerifyBypass_HeadersReplayStillWall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("<html><title>Forbidden</title>forbidden</html>"))
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 5, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)

	wall := fetch(client, target, srv.URL+"/secret", cfg)
	p := Profile{Statuses: map[int]bool{403: true}, Sims: []uint64{wall.Sim}, Threshold: 4}

	hit := &NomoreHit{Technique: "headers", Payload: "X-Forwarded-For: 127.0.0.1", Status: 200}
	label, preview := verifyBypass(client, target, srv.URL+"/secret", hit, p, cfg, hit.String())
	if !strings.HasPrefix(label, "unverified:") {
		t.Fatalf("wall response must stay unverified, got %q", label)
	}
	if preview != "" {
		t.Fatalf("no preview on unverified hit, got %q", preview)
	}
}

// TestVerifyBypass_HeadersReplayInNotFoundEnvelope — the target answers our replay with a
// 2xx that SimHash-matches the calibrated not-found envelope (a WAF happy-path shell).
// isNotFound catches it and the label must stay "unverified:*" — a fake bypass parading
// as a real one is the exact false-positive the finding calls out.
func TestVerifyBypass_HeadersReplayInNotFoundEnvelope(t *testing.T) {
	// Both wall probe and header replay return the SAME 200 shell body, so the
	// isNotFound check trips.
	shell := "<html><title>Welcome</title>please log in</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/")
	cfg := &Config{Timeout: 5, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)

	baseline := fetch(client, target, srv.URL+"/secret", cfg)
	p := Profile{Statuses: map[int]bool{200: true}, Sims: []uint64{baseline.Sim}, Threshold: 4}

	hit := &NomoreHit{Technique: "headers", Payload: "X-Forwarded-For: 127.0.0.1", Status: 200}
	label, preview := verifyBypass(client, target, srv.URL+"/secret", hit, p, cfg, hit.String())
	if !strings.HasPrefix(label, "unverified:") {
		t.Fatalf("shell replay matches not-found envelope — must stay unverified, got %q", label)
	}
	if preview != "" {
		t.Fatalf("no preview when replay matches baseline, got %q", preview)
	}
}

// TestVerifyBypass_NonHeaderTechniqueUnverified — verb tunneling and endpaths payloads
// aren't safely rebuildable from a plain GET; the finding says "keep unverified for
// techniques sift can't replay". Confirm the code paths for verbs, endpaths and
// path-case all bypass the network call and label the hit unverified.
func TestVerifyBypass_NonHeaderTechniqueUnverified(t *testing.T) {
	// Deliberately point at a URL that would panic dial if the code tried to reach it —
	// non-header techniques must NOT trigger a fetch.
	cfg := &Config{Timeout: 5, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	target, _ := url.Parse("http://127.0.0.1:1/")
	p := Profile{Statuses: map[int]bool{403: true}, Sims: []uint64{0xDEAD}, Threshold: 4}

	for _, tech := range []string{"verbs", "endpaths", "path-case"} {
		hit := &NomoreHit{Technique: tech, Payload: "PUT", Status: 200}
		label, preview := verifyBypass(client, target, "http://127.0.0.1:1/x", hit, p, cfg, hit.String())
		if !strings.HasPrefix(label, "unverified:") {
			t.Fatalf("%s must stay unverified, got %q", tech, label)
		}
		if preview != "" {
			t.Fatalf("%s must not carry a preview, got %q", tech, preview)
		}
	}
}

// TestVerifyBypass_MalformedHeaderPayload — a payload with no colon or an empty header
// name can't be rebuilt as a header; treat as unverified rather than send a broken request.
func TestVerifyBypass_MalformedHeaderPayload(t *testing.T) {
	cfg := &Config{Timeout: 5, UA: "sift-test", Concurrency: 1}
	client := mustNewClient(t, cfg)
	target, _ := url.Parse("http://127.0.0.1:1/")
	p := Profile{Statuses: map[int]bool{403: true}, Sims: []uint64{0xDEAD}, Threshold: 4}

	for _, payload := range []string{"nope", ":empty-name", ""} {
		hit := &NomoreHit{Technique: "headers", Payload: payload}
		label, preview := verifyBypass(client, target, "http://127.0.0.1:1/x", hit, p, cfg, hit.String())
		if !strings.HasPrefix(label, "unverified:") {
			t.Fatalf("malformed payload %q must stay unverified, got %q", payload, label)
		}
		if preview != "" {
			t.Fatalf("malformed payload %q must not carry a preview, got %q", payload, preview)
		}
	}
}

// TestNomoreHit_String — the wire-label roundtrip other callers rely on.
func TestNomoreHit_String(t *testing.T) {
	cases := []struct {
		in   *NomoreHit
		want string
	}{
		{nil, ""},
		{&NomoreHit{Technique: "headers", Payload: "X-Forwarded-For: 127.0.0.1"}, "headers:X-Forwarded-For: 127.0.0.1"},
		{&NomoreHit{Technique: "endpaths"}, "endpaths"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Fatalf("String(%+v)=%q want %q", c.in, got, c.want)
		}
	}
}

// TestBuildBypassPreview_TitleAndTruncation — the preview is a single-line, HTML-escaped
// snapshot capped at 200 body chars. Locks the shape so a report consumer can rely on it.
func TestBuildBypassPreview_TitleAndTruncation(t *testing.T) {
	r := Resp{
		Title: "admin console",
		Body:  "<h1>Users</h1>\n<script>alert(1)</script>" + strings.Repeat("x", 300),
	}
	preview := buildBypassPreview(r)
	if !strings.HasPrefix(preview, "title=admin console") {
		t.Fatalf("preview must start with title=; got %q", preview)
	}
	if strings.Contains(preview, "<script>") {
		t.Fatalf("preview must HTML-escape body; got %q", preview)
	}
	// The body slice was 300 x's tacked onto ~40 chars of prefix, so after 200-char
	// cap and whitespace-collapse the raw body length in the preview is bounded.
	// Cheap check: the preview must not contain a 250-char run of x.
	if strings.Contains(preview, strings.Repeat("x", 250)) {
		t.Fatalf("body must be capped at 200 chars before escaping; got %q", preview)
	}
}
