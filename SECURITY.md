# Security Policy

## Reporting a vulnerability

If you find a vulnerability **in lucid itself** (the code in this repo, not in a target you scanned with it), please report it privately:

- **Email**: can36nar@gmail.com
- **Subject**: `[lucid] security: <one-line summary>`
- **Do not** open a public GitHub issue.

Please include:

- The lucid version (`lucid -version`) — or the commit SHA if built from `main`.
- The exact command line that triggers the issue.
- A minimal reproducer: a wordlist, a decoy target, or a HAR file (`-har out.har`) that demonstrates the vulnerability.
- Impact — what an attacker can do that they couldn't before.

A brief acknowledgement will land within 72 hours. A meaningful update (fix landed, disclosure timeline, or "we won't fix, here's why") lands within 30 days.

## Scope

In scope:

- Vulnerabilities in the Go code under this repository — the orchestrator, cleanup core, HAR export, CI workflows, and audit.
- Vulnerabilities in the way lucid handles operator-supplied data (`-b`, `-u`, `-H`, `-w`, `-o`, `-har`) — command injection, path traversal on output files, credential leakage.
- Vulnerabilities in the way lucid emits output (JSON schema misparse, HAR that leaks unredacted auth despite the redactor).

Out of scope:

- Vulnerabilities in the delegated engines (feroxbuster, ffuf, katana, gau, nomore403) — report those to their maintainers.
- Wordlist quality, false positives, or "why didn't lucid find X on my target" — those are recall issues, not vulnerabilities.
- Scans that hit a target you were not authorized to test.

## What you get

- Credit in the release notes if you want it.
- A CVE request from us if the vulnerability warrants one.
- No bug bounty — this is a personal project, not a commercial product.

## What we ask

- Give us a reasonable disclosure window (30 days by default; longer if the fix is architectural).
- Don't exfiltrate data, disrupt services, or violate any law demonstrating the vulnerability.
- Confirm you're testing against your own installation of lucid, not someone else's live scan.
