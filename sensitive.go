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
	{"okta-client-id", `(?i)"clientId"\s*:\s*"0oa[a-z0-9]{16,}"`},
	{"okta-org", `(?i)"issuer"\s*:\s*"https://[a-z0-9\-]+\.okta(?:preview)?\.com/oauth2/`},
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
