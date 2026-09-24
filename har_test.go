package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildHAR_RedactsAuthHeaders — the exact promise of the export. A HAR shared with
// a report reader must NOT contain the operator's session cookie or Authorization value.
func TestBuildHAR_RedactsAuthHeaders(t *testing.T) {
	caps := []harCapture{{
		URL:    "https://target.tld/admin",
		Method: "GET",
		ReqHeaders: map[string]string{
			"User-Agent":    "sift/0",
			"Cookie":        "session=SECRET123",
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.SECRET.SECRET",
			"X-Api-Key":     "SECRET_KEY",
			"X-Auth-Token":  "SECRET_TOK",
		},
		Status: 200,
		CType:  "text/html",
		Body:   "<html>ok</html>",
	}}
	doc := buildHAR(caps)
	if len(doc.Log.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(doc.Log.Entries))
	}
	headerMap := map[string]string{}
	for _, h := range doc.Log.Entries[0].Request.Headers {
		headerMap[strings.ToLower(h.Name)] = h.Value
	}
	for _, k := range []string{"cookie", "authorization", "x-api-key", "x-auth-token"} {
		if v, ok := headerMap[k]; !ok {
			t.Errorf("redacted header %s missing from output — name must still be present so readers see auth was used", k)
		} else if !strings.Contains(v, "REDACTED") {
			t.Errorf("%s not redacted: %q", k, v)
		}
	}
	if headerMap["user-agent"] != "sift/0" {
		t.Errorf("non-secret header User-Agent must survive: %q", headerMap["user-agent"])
	}
}

// TestBuildHAR_BodyCapAndFlag — bodies past harBodyCap must be truncated by the caller
// (scanner) and the export must flag it so a report reader knows they only got a preview.
func TestBuildHAR_BodyCapAndFlag(t *testing.T) {
	big := strings.Repeat("A", harBodyCap+10)   // scanner would have already cut it; simulate uncut
	trunc := strings.Repeat("A", harBodyCap)     // scanner-truncated shape
	docBig := buildHAR([]harCapture{{URL: "u", Body: big}})
	docTrunc := buildHAR([]harCapture{{URL: "u", Body: trunc}})
	if !docBig.Log.Entries[0].Response.Extra.Truncated {
		t.Error("body larger than cap must set _extra.truncated=true")
	}
	if !docTrunc.Log.Entries[0].Response.Extra.Truncated {
		t.Error("body at exactly cap must also be flagged truncated (>=)")
	}
	docSmall := buildHAR([]harCapture{{URL: "u", Body: "small"}})
	if docSmall.Log.Entries[0].Response.Extra.Truncated {
		t.Error("small body must NOT be marked truncated")
	}
}

// TestWriteHAR_Roundtrip — the file we write must reparse as valid JSON and preserve
// every entry; a CI script piping sift -har into Burp needs a syntactically clean file.
func TestWriteHAR_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.har")
	caps := []harCapture{
		{URL: "https://t/a", Status: 200, CType: "application/json", Body: `{"ok":true}`},
		{URL: "https://t/b", Status: 403, CType: "text/html", Body: "<html>forbidden</html>"},
	}
	if err := writeHAR(path, caps); err != nil {
		t.Fatalf("writeHAR: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed harDocument
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if parsed.Log.Version != "1.2" {
		t.Errorf("HAR version want 1.2, got %q", parsed.Log.Version)
	}
	if len(parsed.Log.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(parsed.Log.Entries))
	}
	if parsed.Log.Entries[0].Response.Status != 200 || parsed.Log.Entries[1].Response.Status != 403 {
		t.Errorf("statuses lost in roundtrip: %v", parsed.Log.Entries)
	}
}

// TestBuildHAR_ResponseHeadersPreserved — analysts triage Findings from Server/Set-Cookie/
// Location/WWW-Authenticate. Those must round-trip into the exported HAR entries.
func TestBuildHAR_ResponseHeadersPreserved(t *testing.T) {
	caps := []harCapture{{
		URL: "https://t/x",
		RespHeaders: map[string]string{
			"Server":           "nginx/1.25",
			"Set-Cookie":       "sid=abc; Path=/; HttpOnly",
			"WWW-Authenticate": "Basic realm=admin",
			"Location":         "/login",
		},
		Status: 302,
	}}
	doc := buildHAR(caps)
	got := map[string]string{}
	for _, h := range doc.Log.Entries[0].Response.Headers {
		got[h.Name] = h.Value
	}
	for _, k := range []string{"Server", "Set-Cookie", "WWW-Authenticate", "Location"} {
		if got[k] == "" {
			t.Errorf("response header %q missing from HAR entry", k)
		}
	}
	// Response headers are NOT redacted — the operator wants them for triage.
	if !strings.Contains(got["Set-Cookie"], "sid=abc") {
		t.Error("Set-Cookie value must be preserved verbatim, not redacted")
	}
}

// TestHARScope_Concurrent — the scope is written from worker goroutines and snapshot()d
// at scan end. Concurrent add() must not race, and snapshot must return a stable copy.
func TestHARScope_Concurrent(t *testing.T) {
	h := &harScope{}
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				h.add(harCapture{URL: "u"})
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	snap := h.snapshot()
	if len(snap) != 400 {
		t.Fatalf("want 400 captures, got %d", len(snap))
	}
	// Mutating the snapshot must NOT affect subsequent snapshots.
	snap[0].URL = "mutated"
	snap2 := h.snapshot()
	if snap2[0].URL == "mutated" {
		t.Error("snapshot returned a shared reference — a caller mutation leaked back")
	}
}

// TestBuildHAR_MultipleSetCookiesEmitDistinctNVPs — the Burp/ZAP contract for HAR imports:
// each Set-Cookie header becomes its own NVP. Joining them into one string is the exact bug
// that made a login response's second cookie (CSRF token) invisible after import.
func TestBuildHAR_MultipleSetCookiesEmitDistinctNVPs(t *testing.T) {
	caps := []harCapture{{
		URL:    "https://t/login",
		Status: 200,
		SetCookies: []string{
			"sid=abc; Path=/; HttpOnly",
			"csrf=xyz; SameSite=Strict",
			"lang=en; Path=/",
		},
	}}
	doc := buildHAR(caps)
	seen := 0
	values := map[string]bool{}
	for _, h := range doc.Log.Entries[0].Response.Headers {
		if h.Name == "Set-Cookie" {
			seen++
			values[h.Value] = true
		}
	}
	if seen != 3 {
		t.Fatalf("expected 3 distinct Set-Cookie NVPs, got %d — Burp will drop session tokens", seen)
	}
	for _, want := range []string{"sid=abc; Path=/; HttpOnly", "csrf=xyz; SameSite=Strict", "lang=en; Path=/"} {
		if !values[want] {
			t.Errorf("Set-Cookie %q lost after buildHAR round-trip", want)
		}
	}
}

// TestBuildHAR_NoSetCookies_NoExtraEntries — the additive path must be a no-op when the
// server didn't emit any Set-Cookie (the common case). We don't want an empty Set-Cookie
// NVP leaking into HARs from ordinary GETs.
func TestBuildHAR_NoSetCookies_NoExtraEntries(t *testing.T) {
	caps := []harCapture{{
		URL:         "https://t/x",
		RespHeaders: map[string]string{"Server": "nginx/1.25"},
		Status:      200,
	}}
	doc := buildHAR(caps)
	for _, h := range doc.Log.Entries[0].Response.Headers {
		if h.Name == "Set-Cookie" {
			t.Errorf("unexpected Set-Cookie NVP on a scan with no cookies: %q", h.Value)
		}
	}
}

// TestBuildHAR_RedirectURLPropagates — a 3xx Finding must land its Location header in
// response.redirectURL so a Burp/ZAP importer shows the chain. Regressing this means an
// analyst importing a HAR sees "/admin 302" with no target, and has to hand-inspect the
// body to find where the redirect went.
func TestBuildHAR_RedirectURLPropagates(t *testing.T) {
	caps := []harCapture{
		{URL: "https://t/admin", Status: 302, RedirectURL: "/login"},
		{URL: "https://t/api", Status: 200}, // 200 has no redirect; must stay empty
	}
	doc := buildHAR(caps)
	if doc.Log.Entries[0].Response.RedirectURL != "/login" {
		t.Errorf("3xx redirectURL lost: got %q", doc.Log.Entries[0].Response.RedirectURL)
	}
	if doc.Log.Entries[1].Response.RedirectURL != "" {
		t.Errorf("200 must have empty redirectURL; got %q", doc.Log.Entries[1].Response.RedirectURL)
	}
}
