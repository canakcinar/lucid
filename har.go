package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
)

// sortStrings is a tiny shim so har.go doesn't have to import "sort" everywhere it's used —
// keeps the callsites readable and the imports minimal.
func sortStrings(s []string) { sort.Strings(s) }

// HAR 1.2 export lets an operator hand every Finding's request+response off to Burp/ZAP/
// mitmproxy for manual replay without re-scanning. Enabled by -har <path>. Captures happen
// lazily inside the scanner (harCap in scanner.go); this file only defines the wire schema
// and the serializer, so a scan that doesn't set -har allocates nothing here.
//
// Security: Cookie and Authorization headers are redacted to "[REDACTED by sift]" before
// serialization — a HAR file is often shared, and leaking the operator's session cookie
// through a bug-bounty attachment is the exact class of accident this tool must not create.

// harBodyCap lives in constants.go — kept centrally so a maintainer changing HAR sizing
// doesn't have to hunt for it inside a specific implementation file.

// harCapture is the per-Finding snapshot the scanner records in memory when cfg.HAROutput
// is non-empty. Kept tiny — just the fields buildHAR() needs — so a 20k-URL scan doesn't
// balloon RAM. All fields are set once (post-fetch) and read once (at scan end).
type harCapture struct {
	URL         string
	Method      string
	ReqHeaders  map[string]string
	Status      int
	CType       string
	Body        string // already truncated to harBodyCap by the caller
	Elapsed     int    // ms
	RespHeaders map[string]string
	// SetCookies carries each Set-Cookie the server sent as a separate string. buildHAR
	// emits them as distinct NVP entries (HAR 1.2 spec + Burp/ZAP contract) instead of a
	// single delimited value — otherwise the importer sees "one cookie" with the delimiter
	// baked in and every subsequent replay ships the wrong session.
	SetCookies []string
	// RedirectURL is the Location header on a 3xx response. sift records but never follows
	// redirects (scope guard); surfacing it in the HAR entry lets Burp/ZAP show the chain
	// so an analyst can see "/admin -> /login" without opening the raw body.
	RedirectURL string
	// StartedDateTime is the ISO-8601 wall-clock time this capture was taken. main() stamps
	// it via time.Now().UTC().Format(time.RFC3339). Empty falls back to a deterministic
	// sentinel so unit tests and diffs stay stable when the caller doesn't care.
	StartedDateTime string
}

// harScope holds the mutex + slice for a running scan's captures. Split from Scanner
// so tests can build a scope without a full Scanner.
type harScope struct {
	mu   sync.Mutex
	caps []harCapture
}

func (h *harScope) add(c harCapture) {
	h.mu.Lock()
	h.caps = append(h.caps, c)
	h.mu.Unlock()
}

func (h *harScope) snapshot() []harCapture {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]harCapture, len(h.caps))
	copy(out, h.caps)
	return out
}

// --- HAR 1.2 wire types. Kept small; we only fill the fields Burp/ZAP actually read.

type harDocument struct {
	Log harLog `json:"log"`
}
type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}
type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            int         `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
}
type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Headers     []harNVP `json:"headers"`
	QueryString []harNVP `json:"queryString"`
	Cookies     []harNVP `json:"cookies"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}
type harResponse struct {
	Status      int          `json:"status"`
	StatusText  string       `json:"statusText"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []harNVP     `json:"headers"`
	Cookies     []harNVP     `json:"cookies"`
	Content     harContent   `json:"content"`
	RedirectURL string       `json:"redirectURL"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
	Extra       harRespExtra `json:"_extra,omitempty"`
}
type harRespExtra struct {
	Truncated bool `json:"truncated,omitempty"`
}
type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}
type harTimings struct {
	Send    int `json:"send"`
	Wait    int `json:"wait"`
	Receive int `json:"receive"`
}
type harNVP struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// redactedHeaders returns request headers with Cookie / Authorization / Proxy-Authorization
// / X-Auth-* values replaced. Header names are preserved so a reader still sees "this scan
// carried auth" without the actual secret.
func redactedHeaders(in map[string]string) []harNVP {
	out := make([]harNVP, 0, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if lk == "cookie" || lk == "authorization" || lk == "proxy-authorization" ||
			strings.HasPrefix(lk, "x-auth-") || strings.HasPrefix(lk, "x-api-key") {
			v = "[REDACTED by sift]"
		}
		out = append(out, harNVP{Name: k, Value: v})
	}
	return out
}

// buildHAR turns the captured entries into a HAR 1.2 document. Every entry shares the
// same creator; startedDateTime comes from harCapture.StartedDateTime when the caller
// populated it (main() timestamps entries as they land) and falls back to a deterministic
// epoch when it's empty so tests and diffs stay stable.
func buildHAR(caps []harCapture) harDocument {
	doc := harDocument{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{Name: "sift", Version: version},
			Entries: make([]harEntry, 0, len(caps)),
		},
	}
	for _, c := range caps {
		hdrs := redactedHeaders(c.ReqHeaders)
		body := c.Body
		truncated := len(body) >= harBodyCap
		startedAt := c.StartedDateTime
		if startedAt == "" {
			startedAt = "1970-01-01T00:00:00Z"
		}
		e := harEntry{
			StartedDateTime: startedAt,
			Time:            c.Elapsed,
			Request: harRequest{
				Method:      firstNonEmpty(c.Method, "GET"),
				URL:         c.URL,
				HTTPVersion: "HTTP/1.1",
				Headers:     hdrs,
				QueryString: []harNVP{},
				Cookies:     []harNVP{},
				HeadersSize: -1,
				BodySize:    0,
			},
			Response: harResponse{
				Status:      c.Status,
				StatusText:  "",
				HTTPVersion: "HTTP/1.1",
				Headers:     mergeRespHeaders(c.RespHeaders, c.SetCookies),
				Cookies:     []harNVP{},
				Content: harContent{
					Size:     len(body),
					MimeType: firstNonEmpty(c.CType, "text/plain"),
					Text:     body,
				},
				RedirectURL: c.RedirectURL,
				HeadersSize: -1,
				BodySize:    len(body),
				Extra:       harRespExtra{Truncated: truncated},
			},
			Timings: harTimings{Send: 0, Wait: c.Elapsed, Receive: 0},
		}
		doc.Log.Entries = append(doc.Log.Entries, e)
	}
	return doc
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// mergeRespHeaders builds the HAR headers array from the named-header map PLUS one entry per
// Set-Cookie the server sent. Distinct NVPs for cookies is the HAR 1.2 shape Burp/ZAP expect
// when they build the session store on import — joining into a single value silently drops
// every Set-Cookie past the first.
func mergeRespHeaders(named map[string]string, cookies []string) []harNVP {
	base := namedHeaders(named)
	if len(cookies) == 0 {
		return base
	}
	out := make([]harNVP, 0, len(base)+len(cookies))
	out = append(out, base...)
	for _, c := range cookies {
		out = append(out, harNVP{Name: "Set-Cookie", Value: c})
	}
	return out
}

// namedHeaders converts sift's Resp.Headers map into the HAR name/value array. Order is
// stable (map iteration order isn't guaranteed) so a diff between two runs stays diff-able.
func namedHeaders(in map[string]string) []harNVP {
	if len(in) == 0 {
		return []harNVP{}
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]harNVP, 0, len(keys))
	for _, k := range keys {
		out = append(out, harNVP{Name: k, Value: in[k]})
	}
	return out
}

// writeHAR serializes to path. Returns an error the caller reports to stderr; a HAR
// write failure must NOT fail the whole scan — the operator still has the JSON findings.
func writeHAR(path string, caps []harCapture) error {
	doc := buildHAR(caps)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600) // 0600: HAR carries request bodies; keep it operator-only
}
