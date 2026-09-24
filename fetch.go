package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var errBudget = errors.New("request budget exceeded")

// parseProxy validates a -x proxy value and returns the parsed URL, requiring
// both a scheme (http/https/socks5/socks5h) and a host. A malformed proxy value
// (typo, wrong scheme, missing host) MUST be fatal upstream: silently falling
// back to a direct connection leaks -b Cookie and -H headers to the origin,
// which is worse than aborting when the operator relied on -x as a safety net.
func parseProxy(raw string) (*url.URL, error) {
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	switch pu.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("invalid proxy URL %q: scheme must be http, https, socks5 or socks5h (got %q)", raw, pu.Scheme)
	}
	if pu.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing host", raw)
	}
	return pu, nil
}

// Resp is a normalized view of one HTTP response plus its SimHash.
type Resp struct {
	URL      string
	Status   int
	Body     string
	Len      int
	Sim      uint64
	Title    string
	CType    string // Content-Type (no params)
	Via      string // Location, when this was a redirect
	OffScope bool   // final/redirect target left the target host
	Err      error
	// Headers holds a small, HAR-relevant subset of response headers. Set only when the caller
	// asked for them (see fetchWithHeaders); a bare fetch() leaves this nil so the hot path
	// (20k-URL scans without -har) doesn't allocate a map per request.
	Headers map[string]string
	// Cookies is the raw Set-Cookie header slice — one entry per Set-Cookie the server
	// emitted. Kept out of Headers (which is map[string]string) because a HAR consumer
	// (Burp/ZAP) expects one NVP per Set-Cookie, not a delimited join, or session state
	// gets misparsed on import.
	Cookies []string
}

func newClient(cfg *Config) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
		MaxIdleConns:    200,
		MaxConnsPerHost: cfg.Concurrency + cfg.Probes + 4,
		// Setting TLSClientConfig disables net/http's implicit h2 upgrade path — modern IoT/API
		// hosts negotiate HTTP/2 over ALPN; without this every request silently downgrades to
		// HTTP/1.1 and multiplexing is lost.
		ForceAttemptHTTP2: true,
	}
	if cfg.Proxy != "" {
		// Fail loudly on a bad -x value. Prior behavior parsed with err==nil and silently
		// dropped an invalid proxy, sending -b/-H auth headers straight to the origin.
		pu, err := parseProxy(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		// A discovery tool records redirects, it doesn't chase them: we always keep the 3xx.
		// This exposes canonical dir redirects (/admin -> /admin/) and can never wander off scope.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func fetch(client *http.Client, target *url.URL, rawurl string, cfg *Config) Resp {
	return fetchWith(client, target, rawurl, cfg, nil)
}

// fetchWith is fetch with an optional extra-header map merged on top of cfg.Headers.
// Used by the bypass-verification path (a replay of nomore403's winning header technique)
// so a single "Header-Name: value" payload can be tacked onto the same GET without
// duplicating fetch's status/SimHash/title/OffScope wiring. The extra map is applied
// LAST so it overrides cfg.Headers when the two collide — nomore403's winning payload
// wins over an operator-supplied -H default, which is the whole point of the replay.
func fetchWith(client *http.Client, target *url.URL, rawurl string, cfg *Config, extra map[string]string) Resp {
	r := Resp{URL: rawurl}
	if cfg.MaxReq > 0 && atomic.AddInt64(&cfg.reqCount, 1) > int64(cfg.MaxReq) {
		r.Err = errBudget
		return r
	}
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		r.Err = err
		return r
	}
	req.Header.Set("User-Agent", cfg.UA)
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if cfg.Throttle != nil {
		cfg.Throttle.wait()
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Err = err
		return r
	}
	defer func() {
		// Drain any remainder past our 2 MB cap so net/http can return the
		// connection to the idle pool. Close alone only consumes ~2 KiB of the
		// tail, so a body larger than the cap forces the Transport to tear the
		// TCP connection down — under a 20k-candidate scan that means thousands
		// of ephemeral ports stuck in TIME_WAIT and FD exhaustion (dial tcp:
		// cannot assign requested address) that masquerades as WAF hostility.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if cfg.Throttle != nil {
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			cfg.Throttle.penalize()
		} else {
			cfg.Throttle.ok()
		}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // cap 2 MB
	// A truncated body is worse than a failed one. If the peer closes mid-body (WAF cutoff,
	// TLS-level abort after status line, RST after headers), io.ReadAll returns a non-nil
	// error (typically io.ErrUnexpectedEOF) with a partial buffer; ignoring it fed the
	// fragment straight into r.Sim/r.Title/r.Len, so calibrate() would compute a not-found
	// baseline against a shorter probe than the wide envelope actually is (poisoning maxd and
	// widening Threshold, blunting sensitivity for the whole dir), and verify() could collapse
	// a real page into VNotFound because its SimHash matched a truncated envelope. Treat it
	// as a network error — same path r.Err already flows through in verify()/calibrate().
	// io.LimitReader hitting the 2 MB cap does NOT surface here: io.ReadAll converts the
	// resulting io.EOF to nil, so a legitimately-capped 5 MB body still returns readErr==nil.
	if readErr != nil {
		r.Err = fmt.Errorf("read body: %w", readErr)
		return r
	}
	r.Status = resp.StatusCode
	r.Body = string(body)
	r.Len = len(body)
	r.Sim = SimHash(r.Body)
	r.Title = extractTitle(r.Body)
	r.CType = strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		r.Via = loc
		if lu, err := url.Parse(loc); err == nil && lu.Host != "" && lu.Host != target.Host {
			r.OffScope = true
		}
	}
	// HAR-relevant headers — kept behind a Config guard so 20k-URL scans without -har don't
	// pay the map-alloc cost. Set-Cookie is a header SLICE (may repeat) and we surface it as
	// r.Cookies (one entry per Set-Cookie) so buildHAR can emit one NVP per cookie — Burp/ZAP
	// misparse a joined value as a single cookie and drop session state on import.
	if cfg.HAROutput != "" {
		r.Headers = map[string]string{}
		for _, k := range []string{"Server", "Location", "WWW-Authenticate", "X-Powered-By",
			"X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"} {
			if v := resp.Header.Get(k); v != "" {
				r.Headers[k] = v
			}
		}
		if sc := resp.Header.Values("Set-Cookie"); len(sc) > 0 {
			r.Cookies = append(r.Cookies, sc...)
		}
	}
	return r
}

// wsHintRe matches URL paths that name a realtime endpoint by convention
// (…/ws, …/socket, …/socket.io, …/stream, …/events). Case-insensitive; matches
// as a path segment so /wsdl or /streamer/foo don't false-positive.
var wsHintRe = regexp.MustCompile(`(?i)(^|/)(ws|socket|socket\.io|stream|events)(/|$|\?)`)

// wsPathHint returns true when the URL's path suggests a WebSocket endpoint
// so the WS-upgrade probe should run even when the plain GET succeeded with a
// non-4xx status (some gateways answer plain GETs with a 200 hello page and
// only speak WebSocket on the same URL after an Upgrade).
func wsPathHint(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	return wsHintRe.MatchString(u.Path)
}

// wsProbe issues a raw HTTP/1.1 GET with WebSocket-Upgrade headers against
// rawurl and returns the server's status code (0 on transport error). Only
// the status line is consumed and the connection is closed right after —
// we're detecting a 101 handshake, not staying subscribed to a stream.
// A dedicated raw conn is used rather than the shared *http.Client because
// net/http's Transport does NOT surface 101 responses through Do(): it
// treats them as protocol switches and returns an error to the caller,
// which would make Kind="ws" undetectable.
func wsProbe(target *url.URL, rawurl string, cfg *Config) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	if u.Host == "" {
		return 0, errors.New("ws probe: empty host")
	}
	hostPort := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" || u.Scheme == "wss" {
			hostPort = net.JoinHostPort(u.Hostname(), "443")
		} else {
			hostPort = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if u.Scheme == "https" || u.Scheme == "wss" {
		conn, err = tls.DialWithDialer(dialer, "tcp", hostPort, &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
			ServerName:         u.Hostname(),
		})
	} else {
		conn, err = dialer.Dial("tcp", hostPort)
	}
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return 0, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&sb, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&sb, "User-Agent: %s\r\n", cfg.UA)
	fmt.Fprint(&sb, "Upgrade: websocket\r\n")
	fmt.Fprint(&sb, "Connection: Upgrade\r\n")
	fmt.Fprint(&sb, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&sb, "Sec-WebSocket-Key: %s\r\n", key)
	for k, v := range cfg.Headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	fmt.Fprint(&sb, "\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return 0, err
	}

	br := bufio.NewReader(io.LimitReader(conn, 8192))
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("ws probe: bad status line %q", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	return code, nil
}
