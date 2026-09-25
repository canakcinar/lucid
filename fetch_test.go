package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestNewClient_HTTP2Enabled makes sure newClient's Transport actually
// negotiates HTTP/2 over TLS. A non-nil TLSClientConfig disables the
// Transport's implicit h2 setup unless ForceAttemptHTTP2 is set (or
// NextProtos/ConfigureTransport is used); before this was fixed every
// request silently fell back to HTTP/1.1 regardless of ALPN.
func TestNewClient_HTTP2Enabled(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Advertise h2 (and http/1.1 as a fallback) via ALPN so a client that
	// speaks HTTP/2 will pick it.
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	defer srv.Close()

	cfg := &Config{
		Concurrency: 1,
		Timeout:     5,
		Insecure:    true, // httptest uses a self-signed cert
		UA:          "lucid-test",
	}
	client, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 negotiation, got %s (ProtoMajor=%d) — Transport.ForceAttemptHTTP2 likely not set",
			resp.Proto, resp.ProtoMajor)
	}
}

// TestNewClient_BadProxyFailsClosed guards the -x safety net. A malformed proxy
// value (typo, wrong scheme, missing host) MUST make newClient return an error
// so main.go aborts, because silently going direct would leak -b Cookie and -H
// auth headers to the origin the operator was trying to route through Burp.
func TestNewClient_BadProxyFailsClosed(t *testing.T) {
	cases := map[string]string{
		"typo scheme":    "htp://127.0.0.1:8080",
		"missing scheme": "127.0.0.1:8080",
		"missing host":   "http://",
		"garbage":        "::::not a url",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Proxy: raw, Timeout: 5, UA: "lucid-test"}
			c, err := newClient(cfg)
			if err == nil {
				t.Fatalf("bad proxy %q returned nil error and client=%v — auth headers would leak to origin", raw, c)
			}
			if c != nil {
				t.Fatalf("bad proxy %q returned non-nil client alongside error — caller may use it and skip the check", raw)
			}
		})
	}
}

// TestNewClient_GoodProxyInstalled proves the happy path is unaffected: a
// well-formed proxy URL installs a non-nil Transport.Proxy so the request
// actually routes through it.
func TestNewClient_GoodProxyInstalled(t *testing.T) {
	cfg := &Config{Proxy: "http://127.0.0.1:8080", Timeout: 5, UA: "lucid-test"}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport not *http.Transport: %T", c.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("valid -x URL produced Transport.Proxy=nil — requests would go direct")
	}
}

// TestFetch_ReusesConnectionOnOversizedBody proves fetch() drains the response
// body past the 2 MB cap so net/http can return the connection to the idle
// pool. Before the drain fix, io.LimitReader left ~3 MB of unread bytes and the
// subsequent Close only consumed ~2 KiB of the tail — every large response
// tore the TCP connection down, causing FD / TIME_WAIT churn under real scans.
// We assert the underlying net.Conn is reused across two sequential fetches by
// counting server-side Accepts.
func TestFetch_ReusesConnectionOnOversizedBody(t *testing.T) {
	var accepts int64
	// 5 MB payload — well above the 2 MB cap.
	payload := make([]byte, 5<<20)
	for i := range payload {
		payload[i] = 'a'
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	srv.Config.ConnState = func(_ net.Conn, cs http.ConnState) {
		if cs == http.StateNew {
			atomic.AddInt64(&accepts, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	cfg := &Config{Concurrency: 1, Timeout: 10, UA: "lucid-test"}
	client, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	tu, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	for i := 0; i < 2; i++ {
		r := fetch(client, tu, srv.URL, cfg)
		if r.Err != nil {
			t.Fatalf("fetch %d: %v", i, r.Err)
		}
		if r.Status != 200 {
			t.Fatalf("fetch %d status=%d", i, r.Status)
		}
		// The 2 MB cap must still apply — we don't want to keep the whole body.
		if r.Len != 2<<20 {
			t.Fatalf("fetch %d Len=%d, want %d (cap must hold)", i, r.Len, 2<<20)
		}
	}

	if n := atomic.LoadInt64(&accepts); n != 1 {
		t.Fatalf("server saw %d new connections across 2 sequential fetches; want 1 (keep-alive is broken: body not drained past 2 MB cap)", n)
	}
}

// TestFetch_TruncatedBodyReportsError guards the classifier against being fed
// a partial body. Before this fix, io.ReadAll's error was discarded: a peer
// that closed mid-body (WAF cutoff, RST after headers) still produced a Resp
// with r.Err == nil and r.Body/r.Sim/r.Title/r.Len taken from the fragment. A
// truncated 200 poisoned the not-found baseline (widened Threshold, blunted
// sensitivity) and could also collapse a real page into VNotFound at verify()
// time. Now readErr must propagate as r.Err so calibrate()/verify() take the
// failed-fetch path — same as a network error — and skip the sample entirely.
func TestFetch_TruncatedBodyReportsError(t *testing.T) {
	// Hijack the connection and lie: Content-Length says 100 000, we send 50
	// bytes and slam the socket closed. io.ReadAll must return
	// io.ErrUnexpectedEOF, which fetch must convert to r.Err.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter is not a Hijacker")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()
		// Status line + headers advertising 100 000 bytes, then only 50.
		fmt.Fprint(buf, "HTTP/1.1 200 OK\r\n")
		fmt.Fprint(buf, "Content-Type: text/html\r\n")
		fmt.Fprint(buf, "Content-Length: 100000\r\n")
		fmt.Fprint(buf, "Connection: close\r\n")
		fmt.Fprint(buf, "\r\n")
		buf.WriteString(strings.Repeat("a", 50))
		buf.Flush()
		// Abort — connection torn down before Content-Length is met.
	}))
	defer srv.Close()

	cfg := &Config{Concurrency: 1, Timeout: 5, UA: "lucid-test"}
	client, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	tu, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	r := fetch(client, tu, srv.URL, cfg)
	if r.Err == nil {
		t.Fatalf("truncated body must surface r.Err; got Status=%d Len=%d Sim=%x — partial content would be classified as authoritative",
			r.Status, r.Len, r.Sim)
	}
	// Once r.Err is set, the classifier fields must NOT carry data derived from
	// the partial fragment — verify()/calibrate() bail on r.Err first, but a
	// future caller reading Body/Sim on a failed Resp must see zero values.
	if r.Body != "" || r.Len != 0 || r.Sim != 0 || r.Title != "" {
		t.Fatalf("failed fetch leaked partial data: Body=%q Len=%d Sim=%x Title=%q",
			r.Body, r.Len, r.Sim, r.Title)
	}
}

// TestNewClient_NoProxy keeps the no-proxy case honest: Transport.Proxy stays
// nil (net/http won't reach for a proxy on its own).
func TestNewClient_NoProxy(t *testing.T) {
	cfg := &Config{Timeout: 5, UA: "lucid-test"}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport not *http.Transport: %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("no -x should leave Transport.Proxy=nil")
	}
}
