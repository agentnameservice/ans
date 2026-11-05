package logstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The SQLite/POSIX deployment has one ingest writer. Keep that boundary across
// processes as well as goroutines; a second process must not bypass the
// service's check/append/index serialization or race startup recovery.
func acquireWriterLock(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logstore: create writer directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".ans-writer.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("logstore: open writer lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // File descriptors fit in the OS int ABI.
		return nil, errors.Join(fmt.Errorf("logstore: another writer owns %q: %w", dir, err), f.Close())
	}
	return f, nil
}

func releaseWriterLock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // File descriptors fit in the OS int ABI.
	return errors.Join(err, f.Close())
}
