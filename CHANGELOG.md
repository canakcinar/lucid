# Changelog

All notable changes to lucid are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [v0.1.0] — 2026-09-24

Initial release. Content-discovery orchestrator over ffuf / feroxbuster / katana / gau / nomore403 with per-directory soft-404 calibration + SimHash cleanup, verified nomore403 bypass, and HAR 1.2 export.

### Features
- Three ferox aggressiveness profiles selected with `-mode`: `fast` (no recursion, no extensions), `standard` (no recursion, extensions), `deep` (recursion + extensions).
- Per-directory soft-404 calibration + SimHash judge; borderline pages surface as `[review]` instead of vanishing.
- `-t <URL>` for a single target and `-f <file>` for a nmap-style list. In multi-target mode `-o`, `-har`, `-checkpoint`, `-resume`, and `-diff` are treated as directories with per-target slugged files.
- `-har out.har` writes a HAR 1.2 export of every finding's request + response for import into Burp / ZAP / mitmproxy. `Cookie`, `Authorization`, `X-Api-Key`, and `X-Auth-*` headers are redacted.
- Actionable-only console output by default: real 200s, secrets (with matched values), verified bypass, `kind:config` leaks, notes, and review-band rows. `-verbose` prints everything. URLs are wrapped in OSC 8 escape sequences so terminals that support it render clickable links.
- Verified vs. unverified bypass labels: `verified:*` means lucid replayed nomore403's technique (headers, verbs, endpaths, path-case) and it cleared the wall; `unverified:*` is a lead for manual triage.
- Secret matches carry the actual matched substring (truncated to 200 chars) alongside the pattern name, so console and JSON both surface what leaked, not just that something leaked.
- Auto-derived engine timeouts from wordlist × rate; `meta.partial_reason` in `-o` JSON names which engine truncated when coverage drops to `partial`.
- Crash-safe: `-checkpoint` writes findings + candidate / profile caches so a killed scan resumes without re-crawling.
- Cross-platform: CI matrix runs on ubuntu / macOS / Windows.
- 14-check integration audit (`lucid -audit`) exercises every engine wrapper against an in-process mock target.

### Requirements
- Go 1.22 or newer.
- Engine binaries (feroxbuster, ffuf, katana, gau, nomore403) must be on `PATH`; each engine is optional and the missing ones are skipped in the audit and in scans.

### License
MIT.

[v0.1.0]: https://github.com/canakcinar/lucid/releases/tag/v0.1.0
