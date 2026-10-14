package logstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriterLock_ExclusiveAndReleased(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireWriterLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireWriterLock(dir); err == nil {
		_ = releaseWriterLock(second)
		t.Fatal("two writers acquired the same storage")
	}
	if err := releaseWriterLock(first); err != nil {
		t.Fatal(err)
	}
	afterClose, err := acquireWriterLock(dir)
	if err != nil {
		t.Fatalf("closed writer retained the lock: %v", err)
	}
	if err := releaseWriterLock(afterClose); err != nil {
		t.Fatal(err)
	}
}

func TestWriterLock_InvalidStorage(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireWriterLock(filepath.Join(blocker, "child")); err == nil {
		t.Fatal("invalid directory accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, ".ans-writer.lock"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireWriterLock(dir); err == nil {
		t.Fatal("invalid lock file accepted")
	}
}
