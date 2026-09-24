# Changelog

All notable changes to sift are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [v0.1.4] — 2026-09-24

Architectural fix for the "ferox truncates on every real target" problem. v0.1.3 measured the recursion cost accurately (1400–1550s) but left the recursion in place; v0.1.4 removes the recursion because that work belongs to katana. Ferox now covers "unlinked path" surface only. Live sanity on the same two targets round-7 measured: coverage went from **partial → complete**, findings held (195→197 on www.cyberwhiz, 4→5 on otatool).

### Changed
- **`runFerox` now passes `-n` (`--no-recursion`)**. Default ferox re-fuzzes the entire wordlist inside every 2xx/3xx/401/403 hit; at `-d 3` on a rich host this executes roughly `hit_count^depth` requests (round-7 measurement: 46,560 requests for common.txt on www.cyberwhiz, ≈10× baseline). Recursion is now katana's job (link extraction from HTML + JS), which is what it's uniquely good at. Ferox does one clean pass over the wordlist.
- **`feroxBudget` rewritten**: `lines × (1 + len(exts)) × 2 / rate`. The `(1 + len(exts))` factor was missing in v0.1.4-rc1 and re-truncated the sanity sweep (`-e php,json,txt,config,bak` turns each word into 6 requests). Empirical baseline for common.txt at rate 30 with no extensions: ≈316s; with 5 extensions: ≈1900s. Both match sanity-run finish times to within the hedge.
- **Tests**: `TestFeroxBudget_ScalesWithWordlist` → `TestFeroxBudget_NoRecursionSinglePass` (bounds 200–500s, no-ext baseline). Added `TestFeroxBudget_IgnoresDepth` (regression guard for anyone re-adding MaxDepth to the formula) and `TestFeroxBudget_ExtensionMultiplier` (regression guard for the -rc1 miss).

### Notes
- If a maintainer needs deep unlinked-path discovery in the future, the answer is **not** to re-enable ferox recursion — it's to run ferox again against the discovered sub-paths in a targeted second pass, so the operator controls the request budget explicitly.

## [v0.1.3] — 2026-09-24

Empirical timeout calibration. The v0.1.2 formula (`lines × depth × 1.5 / rate`) predicted 712s for common.txt at rate 30, but two round-7 measurements against real hosts — running raw feroxbuster with no timeout — showed the true wall-clock is nearly 2× that:

| target | wall-clock | v0.1.2 predicted | ratio |
| :-- | :-- | :-- | :-- |
| www.cyberwhiz.co.uk (rich content) | 1552s | 712s | 2.18× |
| otatool.arcelikiot.com (mid-density API) | 1374s | 712s | 1.93× |

### Changed
- **`feroxBudget` hedge multiplier: 1.5 → 3.0**. common.txt at -depth 3 -rate 30 now derives 1425s instead of 712s, matching the measured 1400–1550s band. The 3.0× absorbs ferox's recursion overhead (each 200 hit re-fuzzes the whole wordlist inside the sub-directory, non-linear with hit density). Every future change to this constant should carry a new measurement — the `feroxBudget` comment block documents the empirical origin so a maintainer doesn't guess.

### Notes
- Measurements + methodology captured in the round-7 scratchpad (`round7/calibrate/measure.log`).
- The `TestFeroxBudget_ScalesWithWordlist` bounds are now 1200 ≤ derived ≤ 2000; the old bounds (400 ≤ x ≤ 1200) would have let the 1.5× regression pass.

## [v0.1.2] — 2026-09-24

Field-driven release: closes the 7 gaps the round-5 24-target sweep (CyberWhiz + arcelikiot, both authorized) exposed. Every fix has a test anchoring it; `sift -audit` still ships 14/14 green.

### Added
- **Auto-derived engine timeout for ferox / ffuf**. `feroxBudget(cfg, wordlist)` reads the wordlist line count and derives `lines × (depth-cap 3) × 3/2 / rate`, with a 60s floor and a fallback to `-engine-timeout` when the wordlist is unreadable. common.txt (4750 words) at `-rate 30` now derives ~712s instead of truncating at the flat 300s default. `-engine-timeout` on the CLI still wins (`engineTimeoutSetByUser` guard via `flag.Visit`) so an operator can override for exotic cases.
- **`meta.partial_reason`** in the `-o` JSON. When `coverage: partial`, the field names WHICH engine truncated (e.g. `feroxbuster_timeout,nomore403_timeout` or `fetch_errors`, `dir_blind:/api/`). A CI script gating on partial no longer has to grep stderr to know whether to raise `-engine-timeout` or retry the whole run. `setPartialReason()` dedupes so the same reason doesn't stack.
- **`kind: config`** — a 200 JSON/JS response whose URL matches a build-config filename (`config.json`, `manifest.json`, `runtime-config.json`, `env.js`, etc.) AND whose body contains an outbound service URL (AWS API Gateway, S3, Okta, Firebase, Azure Blob, GCP Storage) gets tagged. The round-5 sweep found live examples (`otatool.arcelikiot.com/config.json` with Okta client IDs; `mailservices.arcelikiot.com/jsAlt/config.json` with AWS API Gateway URLs) that would have been dismissed as "static assets" without this signal.
- **Secret pattern surface** extended: `okta-client-id` now matches all four spellings (`clientId`, `client.id`, `client_id`, `oktaClientId`) — the strict variant missed the dot form found on `otatool`. New patterns for `aws-api-gateway`, `aws-s3-bucket`, `azure-blob`, `gcp-storage`, `firebase-db` surface architecture-leak URLs as leads (they're not "secrets" in the strict sense, but a bug-bounty operator wants to know they're there).
- **Timeout-philosophy comment block** at the top of `engines.go`: documents WHY every engine is bounded (adversarial hosts, engine bugs, batch throughput, partial > silent) rather than "wait until done". Answers the design question a reviewer will ask.
- **7 tests** in `round6_test.go` — one per fix. Coverage stays green under `-race`.

### Changed
- `truncWarn` / `engineRunErr` now record the failing engine's name in `Config.PartialReason` when they flip `Truncated`. `ResetRuntime()` clears both, so a library caller reusing the same Config across scans doesn't carry stale reasons into the next run.

## [v0.1.1] — 2026-09-24

Housekeeping release. **Rewrites v0.1.0's history to purge accidentally-committed engagement scan JSONs** and adds the CI + test coverage that v0.1.0's audit round-4 missed. The v0.1.0 tag is deleted and replaced by v0.1.1 — anyone who already fetched v0.1.0 should re-clone.

### Fixed
- **Security**: 28 scratch scan JSONs (`s_*.json`, `scan_*.json`, `geoip*.json`) were removed from the working tree AND purged from the entire git history via `git filter-branch`; the working ref backup and reflog were dropped and `git gc --aggressive --prune=now` collapsed them. `.gitignore` now blocks these prefixes at the source so a future `git add -A` can't re-introduce them.

### Added
- **CI matrix**: ubuntu-latest / macos-latest / windows-latest for vet + build + test-short. `procgroup_other.go` (Windows fallback) is now proved compiling on every push. Race job stays on Linux + macOS (the Windows race detector on GitHub's stock image has been fragile historically).
- **Throttle test suite** (`throttle_test.go`, 5 tests): the WAF-adaptive pacer had 0% coverage before. Now covers idle base, penalize doubling + ceiling clamp, ok decay toward base without undershoot, and a 16-worker concurrent CAS stress test that catches a lost-update regression.
- **README**: hot-path benchmark baselines (SimHash / Judge / Collapse) surfaced from `bench_test.go` comments — a future regression >2× on any of them is now a review item, not a silent walk-off.

### Changed
- `README.md` subtitle: test count 126, coverage 65.5%, MIT — real numbers from the current tree, not decayed hardcoded ones.
- Windows caveat rewritten now that CI proves the build; the honest remaining note is runtime-only (grandchild-kill fallback via direct-child signal).

## [v0.1.0] — 2026-09-24 (retracted)

Retracted — see v0.1.1. Tag was deleted from the local repo before any push; the v0.1.0 SHA is no longer reachable.

First tagged release. Content-discovery orchestrator over ffuf / feroxbuster / katana / gau / nomore403, with an in-process cleanup layer (per-directory soft-404 calibration + SimHash) and a HAR 1.2 exporter that hands every finding to Burp / ZAP / mitmproxy for manual replay.

### Added
- **Engines**: ffuf, feroxbuster, katana, gau, nomore403 wrappers with a shared `-engine-timeout` deadline, an auto-derived nomore403 budget (technique × payload × concurrency), and `-rate` propagation to every engine that supports it.
- **Cleanup**: per-directory calibration probes → per-directory soft-404 profile → SimHash judge with a `-review` band just inside the threshold for near-miss triage; `-collapse` merges N+ findings sharing an identical response.
- **Bypass**: nomore403 headers technique verified in-process (real HTTP replay via `verifyBypass`); other techniques surface as `unverified:*` so an operator never confuses a verified vs. self-reported bypass.
- **HAR 1.2 export** (`-har`): every finding's request + response, redirect chain via `redirectURL`, one NVP per `Set-Cookie` (Burp / ZAP contract), redacted `Cookie` / `Authorization` / `X-Auth-*` / `X-Api-Key` headers, real `startedDateTime` per capture; `-har-required` turns a write failure into a nonzero exit.
- **Resume + diff**: `-checkpoint` writes a JSONL of findings with sibling candidate + profile caches so a killed scan resumes without re-crawling; `-diff` tags URLs whose observable signal drifted against a baseline (status / kind / bypass), not just presence.
- **Passive discovery**: robots.txt, sitemap.xml (with same-host guard), `.well-known/*`, and OpenAPI probes (swagger.json, v2 / v3 api-docs).
- **Auth**: `-b` cookie, `-u user:pass` HTTP Basic (with a `-force-empty-pass` opt-in so appliances that use empty passwords are supported explicitly, not by accident), `-H` repeatable extra headers.
- **Signal handling**: SIGINT / SIGTERM tears down every engine's context, drains registered temp files (`sift-*.json` scratch), and kills each engine's process group (Unix) so non-interactive runs (systemd / nohup / cron) don't leak grandchildren.
- **Self-check**: `-audit` stands up an in-process `httptest` server and drives every engine wrapper end-to-end — 14 integration checks; the wire count is asserted exactly by `TestRunAudit_Integration`.
- **`-version`**: prints the ldflags-injected version and exits (no URL required); default `-ua` string picks up the same value.
- **CI**: GitHub Actions matrix runs `go vet` + build + `go test -short` on every push, plus a `-race` job and an audit + integration job.
- **License**: MIT.

### Notes for downstream users
- Requires Go 1.22 or newer.
- `-audit` runs in ~13 s on a stock CI runner; the default `go test ./...` suite is ~1 s (integration and benchmark suites are behind build tags).
- Verify by tag: `go install github.com/canakcinar/sift@v0.1.0` and run `sift -version`.

[Unreleased]: https://github.com/canakcinar/sift/compare/v0.1.4...HEAD
[v0.1.4]: https://github.com/canakcinar/sift/releases/tag/v0.1.4
[v0.1.3]: https://github.com/canakcinar/sift/releases/tag/v0.1.3
[v0.1.2]: https://github.com/canakcinar/sift/releases/tag/v0.1.2
[v0.1.1]: https://github.com/canakcinar/sift/releases/tag/v0.1.1
[v0.1.0]: https://github.com/canakcinar/sift/releases/tag/v0.1.0
