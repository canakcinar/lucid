package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// rootCtx is the parent context every external engine derives from. It is
// context.Background() by default so tests / library callers behave as before;
// installSignalHandler() replaces it with one that cancels on SIGINT/SIGTERM.
//
// Why this exists: Go's default SIGINT behaviour terminates the process without
// running deferred cleanup, so every `defer os.Remove(tmp.Name())` in the engine
// wrappers is skipped and $TMPDIR fills with orphaned scratch files. Worse, in a
// non-interactive run (systemd / nohup / cron / a wrapper that puts sift in its
// own pgid) the child engines (feroxbuster, katana, gau, nomore403) are not
// killed by the terminal's process-group SIGINT — they become orphaned. With a
// signal-aware root context, `exec.CommandContext`'s cancel path fires and the
// engine's process group is torn down, and any temp files registered via
// createTracked are unlinked from the shutdown goroutine below.
var (
	rootCtx    context.Context = context.Background()
	rootCancel context.CancelFunc

	tempFiles sync.Map // string -> struct{}
)

// installSignalHandler wires SIGINT/SIGTERM into rootCtx and starts the temp-file
// drainer. Callers should defer the returned cancel func so the handler is torn
// down on normal exit too (avoids leaking the signal.Notify channel).
func installSignalHandler() context.CancelFunc {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	rootCtx = ctx
	rootCancel = cancel
	go func() {
		<-ctx.Done()
		cleanupTempFiles()
	}()
	return cancel
}

// registerTemp records a path so cleanupTempFiles can unlink it on shutdown.
// Safe to call with an empty string (no-op) so wrapper code stays tidy.
func registerTemp(p string) {
	if p != "" {
		tempFiles.Store(p, struct{}{})
	}
}

// unregisterTemp drops a path from the registry — engines call this after their
// own deferred os.Remove has already unlinked the file on a clean run, so the
// signal handler doesn't waste a syscall on a path that's already gone.
func unregisterTemp(p string) {
	if p != "" {
		tempFiles.Delete(p)
	}
}

// cleanupTempFiles unlinks every currently-registered temp file. Errors are
// swallowed: the file may already be gone (clean deferred removal raced us) and
// there is no useful place to log during a signal-driven shutdown.
func cleanupTempFiles() {
	tempFiles.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			_ = os.Remove(s)
		}
		return true
	})
}

// createTracked wraps os.CreateTemp and registers the resulting path so an
// unclean shutdown (SIGINT/SIGTERM) still removes the file — plain
// `defer os.Remove` doesn't run when the runtime exits from a default signal.
func createTracked(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	registerTemp(f.Name())
	return f, nil
}
