package main

import (
	"os"
	"testing"
)

// TestCleanupTempFiles_RemovesRegistered — the shutdown drainer must unlink every
// file that createTracked (or registerTemp) recorded. This is the whole point of
// the registry: on SIGINT/SIGTERM the runtime skips deferred os.Remove, and this
// path is what stops $TMPDIR from filling with lucid-*.json orphans.
func TestCleanupTempFiles_RemovesRegistered(t *testing.T) {
	f, err := os.CreateTemp("", "lucid-cleanup-test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()
	// Belt-and-braces: if the assertion below ever regresses to a false pass,
	// make sure the fixture doesn't leak into $TMPDIR.
	t.Cleanup(func() { os.Remove(path); unregisterTemp(path) })

	registerTemp(path)
	cleanupTempFiles()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanupTempFiles left %s behind (err=%v); registry didn't drive removal", path, err)
	}
}

// TestUnregisterTemp_StopsCleanup — the clean-exit path relies on the engine's
// own `defer os.Remove` firing first, then calling unregisterTemp so the drainer
// doesn't chase a path that's already gone. This test guarantees unregister
// actually drops the entry.
func TestUnregisterTemp_StopsCleanup(t *testing.T) {
	f, err := os.CreateTemp("", "lucid-cleanup-test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()
	t.Cleanup(func() { os.Remove(path) })

	registerTemp(path)
	unregisterTemp(path)
	cleanupTempFiles()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("unregistered path %s must survive cleanupTempFiles; got err=%v", path, err)
	}
}

// TestCreateTracked_RegistersPath — createTracked is the wrapper the engines use;
// if it forgets to register, the whole handler is inert. Verify the drainer
// picks up a file made via createTracked without an explicit registerTemp call.
func TestCreateTracked_RegistersPath(t *testing.T) {
	f, err := createTracked("", "lucid-cleanup-test-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()
	t.Cleanup(func() { os.Remove(path); unregisterTemp(path) })

	cleanupTempFiles()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("createTracked file %s survived cleanup (err=%v); registration missing", path, err)
	}
}
