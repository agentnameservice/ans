// Package sqlitetl is the SQLite-backed EventStorage for ans-tl.
//
// Tessera owns the Merkle tree and POSIX tile files; this store holds a
// searchable mirror of appended events plus a cache of checkpoints and
// receipts. The interface is modeled after the reference TL's Tessera
// integration so the same shape works when swapped to a managed MySQL
// or Postgres backend in a future cloud-adapter contribution.
package sqlitetl

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // driver

	"github.com/godaddy/ans/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a sqlx.DB shared by the event, checkpoint, and receipt stores.
type DB struct {
	db *sqlx.DB
}

// DBX exposes the sqlx handle for advanced use.
func (d *DB) DBX() *sqlx.DB { return d.db }

// Close releases the underlying handle.
func (d *DB) Close() error { return d.db.Close() }

// Open creates/opens the TL index database at path and applies migrations.
func Open(ctx context.Context, path string) (*DB, error) {
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("sqlite_tl: create dir %s: %w", dir, err)
			}
		}
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if path == ":memory:" {
		dsn = path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	sqlxDB, err := sqlx.ConnectContext(ctx, "sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite_tl: connect: %w", err)
	}
	sqlxDB.SetMaxOpenConns(1)
	sqlxDB.SetMaxIdleConns(1)

	d := &DB{db: sqlxDB}
	if err := d.migrate(ctx); err != nil {
		_ = sqlxDB.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version       TEXT PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        )`); err != nil {
		return fmt.Errorf("sqlite_tl: create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlite_tl: read migrations: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied, err := d.loadAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, f := range files {
		if _, ok := applied[f]; ok {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return fmt.Errorf("sqlite_tl: read %s: %w", f, err)
		}
		tx, err := d.db.BeginTxx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite_tl: apply %s: %w", f, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at_ms)
             VALUES(?, strftime('%s','now')*1000)`, f); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// loadAppliedMigrations reads the schema_migrations table and
// returns a set of versions already applied. Factored out of the
// migrate flow so rows.Close lives on a defer (sqlclosecheck) and
// rows.Err is checked after the loop.
func (d *DB) loadAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlitetl: query applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := map[string]struct{}{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("sqlitetl: scan applied: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitetl: iterate applied: %w", err)
	}
	return applied, nil
}

// mapSQLErr bridges sql.ErrNoRows to domain.ErrNotFound.
func mapSQLErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return domain.NewNotFoundError("TL_NOT_FOUND", err.Error())
	default:
		return err
	}
}

func nowMs() int64 { return time.Now().UnixMilli() }
