package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestInstallSignalHandler_ReturnsCancelAndSwapsRootCtx — installSignalHandler is
// what wires SIGINT/SIGTERM into every engine's derived context. A regression here
// (returning a no-op cancel, forgetting to replace rootCtx) would silently break
// the "Ctrl-C tears down every engine + drains temp files" contract.
//
// The test is careful about global state: rootCtx / rootCancel are process-wide,
// so we save-and-restore them under t.Cleanup and never sit on the goroutine that
// drains temp files (the returned cancel func closes the notify channel).
func TestInstallSignalHandler_ReturnsCancelAndSwapsRootCtx(t *testing.T) {
	prevCtx := rootCtx
	prevCancel := rootCancel
	t.Cleanup(func() {
		rootCtx = prevCtx
		rootCancel = prevCancel
	})

	cancel := installSignalHandler()
	if cancel == nil {
		t.Fatal("installSignalHandler returned a nil cancel func; callers defer this and would nil-panic")
	}
	if rootCtx == prevCtx {
		t.Fatal("installSignalHandler did not swap rootCtx; engineCmd would still derive from context.Background()")
	}

	// Calling cancel should mark rootCtx as done — that's how a clean-exit path
	// tears down the signal handler without leaking the notify channel.
	cancel()
	select {
	case <-rootCtx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancel() did not propagate to rootCtx.Done() within 500ms")
	}
}

// TestKillGroup_NilProcessNoPanic — killGroup is invoked from exec.Cmd.Cancel and
// occasionally races the process's own natural exit; when Process is already nil
// it must be a no-op. Both procgroup_unix.go and procgroup_other.go return nil in
// that case, but the guard is easy to regress on a refactor.
func TestKillGroup_NilProcessNoPanic(t *testing.T) {
	// exec.Cmd{} with no Start() call has Process == nil.
	var cmd = fakeCmdForKillGroup()
	if err := killGroup(cmd); err != nil {
		t.Fatalf("killGroup on nil-process cmd should be a no-op; got err=%v", err)
	}
}

// fakeCmdForKillGroup lives in its own helper so a future refactor that changes
// exec.Cmd's zero value (unlikely) has a single site to fix. Kept out of the
// signals_test.go file so a Windows-only build (procgroup_other.go) still finds
// it beside the killGroup call.
func fakeCmdForKillGroup() *exec.Cmd { return &exec.Cmd{} }

// TestRunFfuf_MissingBinaryReturnsNil — the wordlist/haveBin guard at the top of
// runFfuf is the tool's only defence against calling a binary the host doesn't
// have installed. If it regresses (say, someone re-orders args and drops the
// haveBin check), a scan on a stock CI image would crash at exec.Cmd.Start().
//
// The empty-wordlist path is the cheapest exercise: haveBin isn't even reached,
// but the same nil-return contract must hold — the caller uses `nil` to mean
// "engine unavailable, don't bother the operator".
func TestRunFfuf_MissingWordlistReturnsNil(t *testing.T) {
	cfg := &Config{Concurrency: 1}
	if got := runFfuf("http://example.invalid", "", cfg); got != nil {
		t.Fatalf("runFfuf with empty wordlist should return nil (engine unavailable); got %v", got)
	}
}

// TestRunFfuf_MissingBinaryWithWordlistReturnsNil complements the above: a real
// wordlist path but no ffuf on PATH still returns nil. The test writes a
// throwaway file so the wordlist check passes and haveBin becomes the decisive
// branch. If ffuf HAPPENS to be installed on the CI runner, we skip cleanly —
// the point of this test is the no-binary path, and running ffuf against
// example.invalid would leak time and possibly log noise.
func TestRunFfuf_MissingBinaryWithWordlistReturnsNil(t *testing.T) {
	if haveBin("ffuf") {
		t.Skip("ffuf is installed on this host; TestRunFfuf_MissingBinaryReturnsNil covers only the negative path")
	}
	f, err := os.CreateTemp("", "sift-wl-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("admin\nlogin\n")
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	cfg := &Config{Concurrency: 1}
	if got := runFfuf("http://example.invalid", f.Name(), cfg); got != nil {
		t.Fatalf("runFfuf with ffuf missing must return nil; got %v", got)
	}
}
