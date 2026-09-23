package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStartAuditMock_HappyPath verifies the mock starts, produces a wordlist,
// and closes cleanly. Regression guard for the nil-*os.File panic that used to
// crash `sift -audit` when CreateTemp returned an error.
func TestStartAuditMock_HappyPath(t *testing.T) {
	m, err := startAuditMock()
	if err != nil {
		t.Fatalf("startAuditMock: %v", err)
	}
	defer m.Close()
	if m == nil {
		t.Fatal("startAuditMock returned nil mock without error")
	}
	if m.URL() == "" {
		t.Fatal("mock server URL empty")
	}
	if m.wordlist == "" {
		t.Fatal("wordlist path empty")
	}
	if _, err := os.Stat(m.wordlist); err != nil {
		t.Fatalf("wordlist not created: %v", err)
	}
}

// TestStartAuditMock_CreateTempFails ensures startAuditMock reports the
// CreateTemp failure as an error rather than panicking on a nil *os.File.
// This is exercised by pointing TMPDIR at a non-existent directory so
// os.CreateTemp fails deterministically.
func TestStartAuditMock_CreateTempFails(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "does", "not", "exist")
	t.Setenv("TMPDIR", bad)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("startAuditMock panicked instead of returning error: %v", r)
		}
	}()

	m, err := startAuditMock()
	if err == nil {
		if m != nil {
			m.Close()
		}
		t.Fatal("expected error when TMPDIR is unwritable, got nil")
	}
	if m != nil {
		t.Fatalf("expected nil mock on error, got %+v", m)
	}
}
