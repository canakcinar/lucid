# Changelog

All notable changes to sift are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/canakcinar/sift/compare/v0.1.1...HEAD
[v0.1.1]: https://github.com/canakcinar/sift/releases/tag/v0.1.1
[v0.1.0]: https://github.com/canakcinar/sift/releases/tag/v0.1.0
