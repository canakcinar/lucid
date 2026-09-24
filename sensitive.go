package main

import (
	"regexp"
	"strings"
)

// isSensitive marks paths that must never be silently collapsed into a WAF wall — a real
// exposure here (heapdump, .env, .git, wp-config) is far more consequential than a saved fetch.
// If the wall handling would drop these, we always re-fetch and judge them individually.
var sensitiveRe = regexp.MustCompile(`(?i)(?:/\.git(?:$|/)|/\.env(?:$|\.|/)|/\.svn/|/\.aws/|/\.ssh/|/\.htpasswd|/\.htaccess|/actuator(?:$|/)|/wp-config|/web\.config|/phpinfo|/server-status|/jolokia|/elmah|/trace\.axd|/swagger|/api-docs|/graphql|/backup(?:$|\.|/)|/dump(?:$|\.|/))`)

func isSensitive(u string) bool { return sensitiveRe.MatchString(u) }

// configLikePathRe matches the URL half of the "leaky config" pattern: `config.json`,
// `manifest.json`, `env.js`, `runtime-config.json`, etc. — SPA/PWA build outputs that ship
// environment URLs (AWS/Okta/Firebase) as JSON. Deliberately narrow — a JS asset that
// happens to contain "config" in its filename isn't a decision surface.
var configLikePathRe = regexp.MustCompile(`(?i)/(?:config|env|runtime[-_]?config|app[-_]?config|firebase[-_]?config|manifest|settings)\.(?:json|js)(?:\?|$)`)

// configOutboundRe matches an outbound-service URL a leaky config would carry. If we see
// one of these in the response body of a `config`-shaped URL, kind:config fires and the
// operator gets a "look here" signal that a bare "200 JSON asset" would have hidden.
var configOutboundRe = regexp.MustCompile(`https?://[a-z0-9.\-]{3,80}\.(?:amazonaws\.com|okta(?:preview)?\.com|firebaseio\.com|firebase\.google\.com|blob\.core\.windows\.net|googleapis\.com|azurewebsites\.net)`)

// isConfigLike returns true when a 200 JSON/JS response looks like a leaky app config —
// the URL matches a build-tool config filename AND the body contains an outbound service
// endpoint. Both halves are required: a filename alone can be an empty manifest; a URL in
// the body alone can be an ordinary API response. Only the pair is the "look here" signal.
func isConfigLike(rawURL, contentType, body string) bool {
	if !configLikePathRe.MatchString(rawURL) {
		return false
	}
	// Content-Type check is a soft guard: some servers mis-set JSON as text/plain.
	// The point is to skip HTML shell that happens to be named /config.json (rare but real).
	ct := strings.ToLower(contentType)
	if !strings.Contains(ct, "json") && !strings.Contains(ct, "javascript") && !strings.Contains(ct, "text/plain") && ct != "" {
		return false
	}
	return configOutboundRe.MatchString(body)
}

// decoyFor builds a same-shape but definitely-non-existent URL in the same directory as u.
// If /admin/.env is a name-based WAF block, /admin/.envzzXXXX will 403 the same way.
func decoyFor(rawurl string) string {
	i := strings.LastIndex(rawurl, "/")
	if i < 0 || i == len(rawurl)-1 {
		return ""
	}
	last := rawurl[i+1:]
	// keep the "trigger prefix" (dot, dash, extension) so the WAF sees the same shape; append
	// random tail so a real file won't exist with this name
	tail := "zz" + randToken()[:8]
	return rawurl[:i+1] + last + tail
}

// Secret patterns for the "look at this" tag on 200 JSON/text hits. Deliberately conservative:
// we surface a lead, not "confirmed leak" — a human still opens the file.
var secretPatterns = []struct {
	name, re string
}{
	{"aws-akid", `AKIA[0-9A-Z]{16}`},
	{"aws-secret", `(?i)aws[_-]?secret[_-]?access[_-]?key`},
	{"gcp-key", `AIza[0-9A-Za-z\-_]{35}`},
	{"github-token", `gh[pousr]_[A-Za-z0-9]{36,}`},
	{"slack-token", `xox[baprs]-[A-Za-z0-9\-]{10,}`},
	{"private-key", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`},
	{"jwt", `eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`},
	{"generic-secret", `(?i)(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|bearer\s+[A-Za-z0-9_\-]{20,}|password)["'\s]*[:=]["'\s]*[A-Za-z0-9_\-]{16,}`},
	// Okta client ID: JSON key varies — `clientId`, `client.id`, `client_id`, `oktaClientId`.
	// The round-6 sweep on otatool.arcelikiot.com carried `"client.id": "0oaxo6uywvW6qgvdt697"`
	// which the strict `"clientId"` pattern missed. This variant covers all four spellings.
	{"okta-client-id", `(?i)"(?:client[._ ]?id|oktaClientId)"\s*:\s*"0oa[a-z0-9]{16,}"`},
	{"okta-org", `(?i)"issuer"\s*:\s*"https://[a-z0-9\-]+\.okta(?:preview)?\.com/oauth2/`},
	// AWS API Gateway URLs — the round-6 sweep found production API Gateway hostnames
	// exposed via config.json. Not a "secret" in the strict sense (they're public endpoints)
	// but they leak the backend architecture and give an attacker a starting point for
	// unauth API enumeration. Surfacing as a lead is the right call.
	{"aws-api-gateway", `https://[a-z0-9]{10}\.execute-api\.[a-z0-9\-]+\.amazonaws\.com`},
	// AWS S3 bucket URLs — same architecture-leak class; a bucket name in a JSON config
	// often points to storage the attacker can then probe for public-read misconfigs.
	{"aws-s3-bucket", `https?://[a-z0-9\-.]{3,63}\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com`},
	// Azure Blob storage URLs — Azure equivalent of the S3 pattern above.
	{"azure-blob", `https://[a-z0-9]{3,24}\.blob\.core\.windows\.net`},
	// GCP Cloud Storage URLs.
	{"gcp-storage", `https://storage\.googleapis\.com/[a-zA-Z0-9\-._]{3,63}`},
	// Firebase realtime DB URLs — often used for BaaS backends; exposure gives the app's
	// database endpoint and reveals whether public-read rules are in effect.
	{"firebase-db", `https://[a-z0-9\-]{3,30}\.firebaseio\.com`},
}

var secretREs []*regexp.Regexp

func init() {
	for _, p := range secretPatterns {
		secretREs = append(secretREs, regexp.MustCompile(p.re))
	}
}

// scanSecrets returns the names of patterns that fired against a response body. Empty = clean.
// Only bodies plausibly containing text are scanned (avoid binary asset false hits).
func scanSecrets(body, ctype string) []string {
	if len(body) == 0 || len(body) > 2<<20 {
		return nil
	}
	if ctype != "" && !strings.HasPrefix(ctype, "text/") &&
		!strings.Contains(ctype, "json") && !strings.Contains(ctype, "xml") &&
		!strings.Contains(ctype, "javascript") && !strings.Contains(ctype, "yaml") &&
		!strings.Contains(ctype, "toml") {
		return nil
	}
	var hits []string
	for i, re := range secretREs {
		if re.MatchString(body) {
			hits = append(hits, secretPatterns[i].name)
		}
	}
	return hits
}
