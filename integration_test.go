//go:build integration

// Integration tests are gated behind -tags=integration so a plain `go test ./...` stays
// fast (~1s). These tests spin up real external binaries or exercise the audit's full
// engine-wrapper matrix and each takes seconds to minutes. Run them with:
//   go test -tags=integration -v ./...
// in CI (or locally) when validating a release. Without the tag, they don't compile in
// and `go test ./...` never pays their wall time.

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestRunAudit_Integration — the audit itself runs every engine wrapper against a controlled
// mock. Slow (~15s live) but the single test that exercises runFerox/runFfuf/runKatana/runGau/
// runNomore403 end-to-end. Behind -tags=integration so `go test ./...` doesn't pay this cost.
//
// We capture stdout so we can also assert on the "all N checks passed" line — a return code
// of 0 alone isn't enough: `runAudit` used to return 0 while quietly skipping a check the
// operator installed a binary for, and a "0 exit + short report" would look identical to a
// clean pass.
func TestRunAudit_Integration(t *testing.T) {
	// Capture stdout so we can assert on the summary line as well as the exit code.
	// runAudit prints to os.Stdout directly; swap it in place for the duration of the call.
	origStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wPipe
	// Drain concurrently so a large capture doesn't deadlock on the pipe buffer.
	var captured bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&captured, rPipe)
		close(done)
	}()

	code := runAudit()

	wPipe.Close()
	os.Stdout = origStdout
	<-done
	out := captured.String()

	if code != 0 {
		t.Errorf("runAudit returned %d — some integration check failed. Output tail:\n%s",
			code, tailN(out, 30))
	}
	// The success line is the operator's contract: N checks green. Assert on it so a future
	// runAudit that silently drops a check (or swaps it for a warning-only variant) can't slip
	// past a return-code-only gate.
	// Summary shape changed since binary-missing became informational: the healthy line is
	// now "core checks passed (N/14 rows green) — lucid healthy". A silent downgrade of a
	// core check would still miss this substring, so the guard stays useful.
	if !strings.Contains(out, "core checks passed") || !strings.Contains(out, "lucid healthy") {
		t.Errorf("runAudit output missing the 'core checks passed … lucid healthy' summary line — a check may have been silently downgraded. Tail:\n%s",
			tailN(out, 30))
	}
	// Every check row starts with "│ ". Exact match — the contract is 14 integration checks
	// in a healthy install (ffuf/feroxbuster/katana/gau/nomore403 + WebSocket/HAR/passive
	// probes + calibrator + soft-404 + WAF-collapse + resume + auth + parseNomore403). A
	// slack `<` bound would let a silently-dropped check slip past this gate; if a check is
	// intentionally added or removed, bump this constant AND write a note in CHANGELOG.md.
	const expectedChecks = 14
	rows := strings.Count(out, "│ ")
	if rows != expectedChecks {
		t.Errorf("runAudit rendered %d check rows; expected exactly %d — a check was added, removed, or the printer stopped mid-run",
			rows, expectedChecks)
	}
}

func tailN(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
