# sift 🧹

A content-discovery **orchestrator**. Point it at a URL: mature tools do the discovery and
bypass work, and sift's own **SimHash cleanup core** — the one piece written from scratch —
turns their noisy union into one clean, per-directory-calibrated inventory.

Everything except the SimHash cleanup is delegated to best-in-class tools:

| Job | Tool | sift's own code? |
| :-- | :-- | :-- |
| Brute force (recursive) | **feroxbuster** (or ffuf) | no |
| Crawl + JS endpoints + robots/sitemap | **katana** (`-jc -kf all`) | no |
| Archive (Wayback/CommonCrawl) | **gau** | no |
| 403/401 bypass | **nomore403** | no |
| **Soft-404 cleanup + review** | **sift SimHash** | **yes — the only original logic** |

Every tool is optional: a missing binary is skipped, and each external process is bounded by a
timeout so nothing can hang the run.

## Why this shape
`ffuf`/`feroxbuster` filter by status/size. On an app that returns **200 for everything** with
variable content (ads, nonce, reflected path), size filters break and you drown in false
positives — and no single tool cleans the *combined* output of brute + crawl + archive. sift
fetches the union once, learns what "not found" looks like **per directory** via SimHash
similarity, and keeps only what genuinely differs. Real pages that share the 404 template are
rescued by a distinct `<title>`; borderline pages surface as `[review]` instead of vanishing.

## Install
```bash
go build -o sift .                                              # sift itself
# engines (any subset; installed to $(go env GOPATH)/bin):
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/devploit/nomore403@latest
brew install feroxbuster ffuf
```

## Usage
```bash
./sift [flags] <url>            # flags may come before, after, or around the url
```
```bash
./sift https://target.tld -w wordlist.txt
./sift https://target.tld -w big.txt -e php,html -depth 3 -budget 50000 -o out.json
./sift https://target.tld -w big.txt -b 'session=...' -x http://127.0.0.1:8080
./sift https://target.tld -w big.txt -diff yesterday.json      # only-new monitoring
```

| flag | meaning | default |
| :-- | :-- | :-- |
| `-w` | wordlist handed to feroxbuster/ffuf | — |
| `-e` | extensions for the brute engine (`php,html,json`) | — |
| `-depth` | crawl/recursion depth for katana & ferox | 2 |
| `-c` | concurrent requests (sift's cleanup fetches) | 20 |
| `-t` | request timeout (s) | 15 |
| `-delay` | base delay per request (ms); auto-backoff on 429/503 | 0 |
| `-budget` | max total **sift cleanup** requests (0 = unlimited) | 0 |
| `-rate` | req/s cap passed to engines **and** sift | 0 |
| `-engine-timeout` | per-engine hard timeout (s) | 300 |
| `-max-candidates` | cap on candidate URLs to clean | 20000 |
| `-assets` | include static assets (js/css/img/pdf) | on |
| `-collapse` | merge N+ findings sharing one response (0=off) | 5 |
| `-resume` | prior findings JSON; skip URLs already scanned | — |
| `-x` | proxy | — |
| `-H` / `-b` | extra header / Cookie | — |
| `-probes` | SimHash calibration probes per directory | 4 |
| `-threshold` | SimHash Hamming threshold (`-1`=auto) | -1 |
| `-review` | review-band width just inside threshold (0=off) | 2 |
| `-bypass` / `-archive` | toggle nomore403 / gau | on |
| `-diff` | baseline JSON to tag new paths | — |
| `-o` | write findings as JSON (schema below) | — |
| `-har` | write a HAR 1.2 export of every Finding's request/response (auth headers redacted) | — |
| `-audit` | run the integration self-check and exit (see **Health check**) | off |

### Health check
```bash
./sift -audit
```
Stands up a local mock target, runs every engine end-to-end, and exits nonzero if any
integration is broken (e.g. the `nomore403` payloads path silently changed). Run it after
install and in CI to catch drift before a real scan hides the failure.

## Pipeline
1. **Discover** — run every installed engine, collect the URL union, dedup, scope-filter to the host.
2. **Calibrate per directory** — probe N random paths; their `(status, SimHash, title)` become the
   not-found profile. Probe spread sets an **adaptive threshold** (dynamic 404 → wider). `/api/`
   and `/static/` calibrate separately.
3. **Judge** every candidate three ways:
   - **hit** — new status class, a distinct `<title>` (when the 404 title is stable), or a body
     far enough (Hamming) from every not-found sample;
   - **review** — body just inside the threshold: surfaced as `[review]`, not dropped;
   - **drop** — body deep inside the not-found envelope.
4. **Enrich** — 403/401 findings go to **nomore403** (bounded, rate-limited, ≤2 concurrent). Its
   result is tagged `unverified:` — sift can't replay the exact winning request to SimHash-check
   it, so treat it as a lead to confirm by hand, not a proven bypass.
5. **Output** — colored console + `-o` JSON, tagged with the discovering engine, redirect, and
   bypass. `-diff` marks only what's new since a prior run.

### The SimHash core (`simhash.go`, `cleanup.go`)
64-bit locality-sensitive hash over **log-damped** token frequencies, so a bulky repeated block
can't dominate. Same-template pages stay a few bits apart; a real page is far. Verified in
`simhash_test.go` (soft↔soft ≈ 5, soft↔real ≈ 29).

## Noise control
- **Catch-all/SPA detection** — if the homepage and a random path return near-identical 200s,
  sift prints a warning: brute is low-signal, trust the crawler's JS endpoints. Responses that
  match the app shell are tagged `kind:shell` so a 200 that's just the SPA frame isn't mistaken
  for a real page (this is what makes an exposed-looking `/.git` on an SPA obvious).
- **Evidence on every finding** — JSON carries `type` (content-type), `title`, and `dist` (SimHash
  distance from the not-found baseline; higher = more distinct = higher confidence), so you can
  triage without re-fetching.
- **Asset tagging** — static files (js/css/img/pdf/…) are tagged `kind:asset`; `-assets=false`
  drops them so you see pages, not every image.
- **Same-response collapse** — findings sharing a status and a near-identical body (Hamming ≤ 2)
  merge into one row when ≥ `-collapse` of them exist — e.g. a Cloudflare 403 block page returned
  for 57 blocked dotfiles becomes a single `collapsed:57` row. Every merged URL is kept under
  `members` in the JSON, so nothing is lost — the console just stops flooding.
- **Uniform-wall shortcut** — if a directory's not-found profile is a static 401/403, engine-reported
  hits with that status are collapsed into one `uniform-wall` row without re-fetching. Sensitive
  paths (`.git`, `.env`, `actuator/*`, `wp-config`, `phpinfo`, `swagger`, `heapdump`, backup files)
  are **always** verified individually — an exposure here matters far more than a saved fetch.
- **WAF-pattern-block detection** — a 403 on a sensitive path may be the WAF matching the *name*
  (`.env`, `.git`), not proof the file exists. sift fetches a same-shape decoy in the same dir; if
  it returns an identical 403, the finding is tagged `note:waf-pattern-block` (a lead, not a leak).
- **Secret pattern scan** — 2xx text/JSON bodies are scanned for AWS keys, GCP keys, GitHub/Slack
  tokens, private keys, JWTs, Okta client IDs/issuers, and generic `api_key/secret/password` shapes.
  Matches surface as `[SECRET ...]` in console and `secrets: []` in JSON. **Leads, not confirmations
  — a human still opens the file.**

## Output JSON schema (`-o`)

The `-o` flag emits a wrapper document with a metadata block and the findings array. A CI
script can gate on `meta.coverage == "complete"` without re-parsing stderr.

```json
{
  "meta": {
    "target":   "https://target.tld/",
    "coverage": "complete",     // or "partial" — an engine hit -engine-timeout or too many fetches failed
    "findings": 42,             // == len(findings[]) minus review-band rows; assets are INCLUDED here
    "assets":   17,             // subset of the "findings" count above (unless -assets=false, then excluded from both)
    "review":   3               // borderline rows carried in findings[] with "review": true
  },
  "findings": [
    { "url": "...", "status": 200, "source": "ferox", "dist": 64, "kind": "asset", ... }
  ]
}
```

**Field caveats a CI script must know:**
- `meta.findings` is `len(findings) - meta.review` — assets are a *subset* of it, not
  excluded. Subtracting `meta.assets` from `meta.findings` to get "real page hits" is
  only correct when the scan was run with `-assets=false` (default is `true`).
- `-diff` and `-resume` accept both the wrapper shape above and the legacy bare-array
  format (`[Finding, Finding, ...]`) so older baselines still work.
- `-har` writes a *separate* file (`-har out.har`); its schema is standard HAR 1.2. Request
  Cookie / Authorization / X-API-Key / X-Auth-* headers are replaced with
  `[REDACTED by sift]` so a shared HAR can't leak the operator's session.

## Safety
- **Scope guard** — redirects are recorded, never followed; off-host redirects are dropped.
- **Bounded** — every engine (ferox, ffuf, katana, gau, nomore403) runs under `-engine-timeout`;
  none can hang the scan.
- **Guaranteed coverage** — with `-rate`, sift auto-raises `-engine-timeout` to `lines/rate` so
  the brute engine finishes the whole wordlist (a too-short timeout silently drops late entries).
  If any engine is still cut off, the run ends with `coverage: PARTIAL` instead of a false clean.
- **Rate control that reaches the loud part** — `-rate` is passed to feroxbuster/ffuf/katana/
  nomore403, not just sift's own fetches, plus 429/503 auto-backoff on sift's requests.
- **Caps** — `-max-candidates` bounds how many URLs sift re-fetches (gau is capped at source);
  `-budget` caps sift's own cleanup requests (note: it does not count requests made *inside* the
  external engines — use `-rate`/tool configs for those).

## Honest limits
- Recall is only as good as your wordlist + what the crawlers/archives surface.
- sift re-fetches each candidate once to compute its SimHash (the engines fetched it too), so a
  brute hit costs one extra request — the price of a uniform cleanup pass.
- On a pure SPA, brute finds little (every route is the same shell) — sift now *detects and warns*
  about this and tags `kind:shell`, but real route discovery there comes from katana's JS parsing,
  not brute. A page byte-indistinguishable from the 404 still can't be separated by body alone.
- **Bypass labels: `verified:` vs `unverified:`.** sift replays the `headers` technique in-process
  and checks whether the replay leaves the not-found envelope — a match becomes `verified:headers:
  <payload>` plus a body preview. The other four techniques (`verbs`, `verbs-case`, `endpaths`,
  `path-case`) are not safely reproducible with a plain GET, so they stay `unverified:` — a lead
  for the operator to confirm by hand, not a proven bypass. A clean 403 means "nomore403 found
  nothing", not "unbypassable" — sift's bypass *hit-rate is nomore403's payload coverage*.
- Short structured JSON is handled (validated: real endpoints separate from 200 soft-404 JSON),
  but calibration is inherently weaker on few-token bodies than on full HTML.
- Validated against synthetic servers **and** a real Cloudflare-fronted site (per-directory
  calibration correctly learned 403-based soft-404s); still calibrate `-threshold`/`-collapse`
  per target, since aggressive collapse can merge distinct-but-identically-templated routes
  (SPA shells) — their URLs remain under `members`, but review them.

## Cross-platform

sift builds on macOS, Linux, and Windows (`GOOS=windows go build`). The audit's mock target
is an in-process `httptest` server — no external runtime needed. On Unix the engine wrappers
put child processes into their own process group so Ctrl-C kills grandchildren too
(`procgroup_unix.go`); on Windows the fallback signals the direct child only (`procgroup_other.go`)
because Windows process groups have different semantics.

Engine binaries (feroxbuster, ffuf, katana, gau, nomore403) must be in `PATH` on whichever OS
you run — sift orchestrates them, it does not bundle them.

*For authorized security testing only.*
