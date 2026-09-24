# Contributing

Thanks for looking. lucid is small on purpose — an orchestrator with a single hot path — so a good change is usually a small change that lands with a test.

## Build + run

```bash
go build ./...
./lucid -audit                 # integration self-check, ~13s
./lucid https://target.tld     # real scan
```

You need Go 1.22 or newer. Everything is `go build ./...` — no vendored deps, no code generation.

## Test tiers

lucid keeps three test speeds so a maintainer can pick the right feedback loop:

```bash
go test -short ./...                                   # ~0.5s smoke slice
go test ./...                                          # ~11s full unit suite
go test -tags=integration -v ./...                     # ~15s — stands up httptest + drives every engine wrapper
go test -race ./...                                    # ~20s — race detector on the concurrency stress suite
go test -bench=. -benchmem -run=^$ ./...               # SimHash + judge + collapse baselines
```

Please run at least `go test ./...` and `go vet ./...` before opening a PR. CI runs the same matrix (see `.github/workflows/ci.yml`) so anything green here is green there.

## Adding a check to `lucid -audit`

The integration audit drives every engine wrapper against an in-process mock. The rule is: if a check is added or removed, bump `expectedChecks` in `integration_test.go` **and** note it in `CHANGELOG.md` — the exact-match assertion is there to stop a check from being silently downgraded to a warning.

## Style

- Go standard style — `gofmt` on save. No linter configuration beyond `go vet`.
- Comments explain *why*, not *what*: the code says what it does. If a reviewer would ask "why this way?" write it down; otherwise leave the comment out.
- Constants that describe engine budgets or SimHash thresholds live in `constants.go`. Adding a magic number inline is a review comment.

## Commit messages

Short imperative subject, wrapped body with the *why*. Reference the file + line you touched when it matters. Every commit should build; a broken bisect is annoying to unwind.

## Reporting a bug

Please include:
- `lucid -version` output
- The exact command line you ran
- The tail of stderr (engine warnings) and the JSON meta block from `-o` if you have one
- A minimal reproducer if the bug is scan-dependent (a `curl`-visible endpoint that behaves the way you're describing)

## What's out of scope

- New engines behind `-bypass` other than nomore403 — the verifier is engine-specific and adding an unverified surface would regress the `unverified:*` guarantee.
- Anything that ships a wordlist. lucid is BYO-wordlist; bundled wordlists get stale and inflate the release.
- Anything that touches the target from a passive-only mode (robots / sitemap / .well-known / OpenAPI). Passive discovery must remain read-only.
