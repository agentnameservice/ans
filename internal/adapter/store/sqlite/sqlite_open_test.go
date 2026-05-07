package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_FilePathCreatesParentDir exercises the on-disk path:
// Open creates the parent directory when missing and applies
// migrations. The standard test suite uses :memory: so the
// MkdirAll branch never fires there.
func TestOpen_FilePathCreatesParentDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Two non-existent path segments under tmp — MkdirAll must create
	// both before the connect call would otherwise fail.
	dbPath := filepath.Join(tmp, "data", "ra", "ans.db")
	db, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if db.DBX() == nil {
		t.Fatal("DBX returned nil sqlx handle")
	}
}

// TestOpen_ReusesExistingDB confirms re-opening the same file
// short-circuits migrations (the schema_migrations rows already
// exist) and returns a working DB. Exercises the loadAppliedMigrations
// path that was uncovered by the always-fresh :memory: tests.
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
		t.Fatalf("second Open (should hit applied-migrations short-circuit): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}

// TestOpen_BadPathReturnsError covers the connect-failure branch
// when the parent dir creation succeeds but sqlite3 still rejects
// the DSN. We point at a path under a file (file-as-directory),
// which makes MkdirAll fail.
func TestOpen_BadPathReturnsError(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Create a regular file at "blocker", then try to open a DB at
	// "blocker/ans.db" — MkdirAll will fail because the parent
	// component is a file, not a directory.
	blocker := filepath.Join(tmp, "blocker")
	if err := writeRegularFile(blocker); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(blocker, "ans.db")
	if _, err := Open(context.Background(), dbPath); err == nil {
		t.Error("expected error when parent path is a file")
	}
}

// writeRegularFile creates a 0-byte regular file at path.
func writeRegularFile(path string) error {
	return os.WriteFile(path, []byte{}, 0o600)
}
