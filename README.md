# lucid

[![CI](https://github.com/canakcinar/lucid/actions/workflows/ci.yml/badge.svg)](https://github.com/canakcinar/lucid/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Content-discovery orchestrator. Feeds a URL to ffuf / feroxbuster / katana / gau / nomore403, cleans up the noisy union with per-directory soft-404 calibration and SimHash, and hands you the "look here" list.

## Install

```bash
go install github.com/canakcinar/lucid@latest

# engines (any subset)
brew install feroxbuster ffuf
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/devploit/nomore403@latest
```

Health-check the install:

```bash
lucid -audit
```

## Usage

Single target:

```bash
lucid -t https://target.tld
lucid -t https://target.tld -w wordlist.txt -e php,json,txt
lucid -t https://target.tld -w wordlist.txt -o out.json -har out.har
```

Multiple targets (nmap-style `-iL`):

```bash
lucid -f targets.txt -o out/ -har har/
# targets.txt: one URL per line, `#` starts a comment
```

With `-f`, `-o` and `-har` are treated as directories — each target writes `<dir>/<slug>.json` and `<dir>/<slug>.har`.

Console shows only actionable rows: real 200s, secrets, bypass, config leaks, review-band. URLs are clickable in modern terminals. `-verbose` prints everything.

## Modes

Pick with `-mode`:

- **fast** — ferox no-recursion, no extensions. Cheapest; for first-look sweeps across many hosts.
- **standard** *(default)* — ferox no-recursion, extensions applied.
- **deep** — ferox recursion + extensions. Slowest; for hosts with unlinked sub-directories katana can't see.

Deadlines are derived from wordlist × rate — you don't tune them.

## HAR export

`-har out.har` writes an [**HAR 1.2**](https://w3c.github.io/web-performance/specs/HAR/Overview.html) file — a standard JSON archive of every request lucid made and the response it got. Import it into **Burp Suite**, **OWASP ZAP**, **mitmproxy**, or any browser DevTools to replay findings by hand without re-scanning. `Cookie` / `Authorization` / `X-Api-Key` / `X-Auth-*` headers are redacted so a shared HAR doesn't leak your session.

## Output

Console output is the "look here" cut. Full findings (including 3xx/4xx/asset/shell rows) always land in `-o out.json`:

```json
{
  "meta": {
    "target":         "https://target.tld/",
    "coverage":       "complete",
    "partial_reason": "",
    "findings":       42,
    "assets":         17,
    "review":         3
  },
  "findings": [
    {
      "url":     "https://target.tld/config.json",
      "status":  200,
      "kind":    "config",
      "secrets": ["aws-api-gateway"],
      "secret_matches": [
        {"name": "aws-api-gateway", "value": "https://xyz.execute-api.eu-central-1.amazonaws.com/v2"}
      ]
    }
  ]
}
```

Fields worth watching:

- `bypass: "verified:*"` — lucid replayed nomore403's technique and it cleared the wall.
- `bypass: "unverified:*"` — lucid can't safely replay it. Manual triage.
- `kind: "config"` — 200 JSON/JS config leaking AWS / Okta / Firebase / etc. URLs.
- `note: "waf-pattern-block"` — the 403 was a name-based WAF rule, not a real exposure.
- `coverage: "partial"` — an engine got cut off. `partial_reason` names which.

## Cross-platform

Cross-compiles on macOS, Linux, Windows. CI runs on all three.

## License

MIT.

*For authorized security testing only.*
