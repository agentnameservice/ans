package sqlitetl

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_FilePathCreatesParentDir mirrors the RA-side equivalent
// in package sqlite — the in-memory tests don't traverse the
// MkdirAll branch, so this on-disk run pins it.
func TestOpen_FilePathCreatesParentDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "data", "tl", "ans.db")
	db, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if db.DBX() == nil {
		t.Fatal("DBX returned nil sqlx handle")
	}
}

// TestOpen_ReusesExistingDB exercises the applied-migrations
// short-circuit on second Open.
func TestOpen_ReusesExistingDB(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "ans.db")
	first, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	second, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}

// TestOpen_BadParentReturnsError covers the MkdirAll failure path
// when the requested parent path is a regular file.
func TestOpen_BadParentReturnsError(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(blocker, "ans.db")
	if _, err := Open(context.Background(), dbPath); err == nil {
		t.Error("expected error when parent path is a file")
	}
}
