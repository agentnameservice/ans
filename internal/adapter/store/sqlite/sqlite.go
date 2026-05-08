// Package sqlite provides SQLite implementations of the store ports
// (AgentStore, CertificateStore, EndpointStore, RenewalStore,
// RevocationStore, ByocCertificateStore) plus an outbox table used by
// the RA→TL HTTP client for durable event delivery.
//
// The adapter uses modernc.org/sqlite — a pure-Go transpilation of
// upstream SQLite — so the binaries cross-compile without CGO. Schema
// migrations are embedded; on Open() the database is created if
// missing and migrations are applied. The embedded migration files
// live in migrations/*.sql relative to this package.
package sqlite

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

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // driver

	"github.com/godaddy/ans/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a sqlx.DB and is shared by the repository implementations.
// Use Open to construct one; it applies migrations automatically.
type DB struct {
	db *sqlx.DB
}

// Open creates or opens the database at path and applies pending
// migrations. path == ":memory:" yields an in-memory DB (useful for tests).
func Open(ctx context.Context, path string) (*DB, error) {
	// Ensure the parent directory exists so a first-run config with a
	// relative path like "./data/ra/ans.db" succeeds without operator setup.
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("sqlite: create dir %s: %w", dir, err)
			}
		}
	}
	// Enable foreign-key enforcement and busy timeout so concurrent
	// writers don't immediately fail with SQLITE_BUSY.
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	// In-memory DBs do not support WAL.
	if path == ":memory:" {
		dsn = path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	sqlxDB, err := sqlx.ConnectContext(ctx, "sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: connect: %w", err)
	}
	// SQLite does not do well with many concurrent writers; a single
	// connection serializes writes inside the process.
	sqlxDB.SetMaxOpenConns(1)
	sqlxDB.SetMaxIdleConns(1)

	d := &DB{db: sqlxDB}
	if err := d.migrate(ctx); err != nil {
		_ = sqlxDB.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the underlying database handle.
func (d *DB) Close() error { return d.db.Close() }

// DBX returns the underlying sqlx.DB for advanced use (transactions).
func (d *DB) DBX() *sqlx.DB { return d.db }

// migrate applies every migration file in order. Migration files are
// embedded from migrations/*.sql; the filename prefix (NNN_) determines
// ordering. A schema_migrations table tracks applied versions.
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        )`); err != nil {
		return fmt.Errorf("sqlite: create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlite: read migrations: %w", err)
	}

	// Sort alphabetically so 001_ comes before 002_.
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
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return fmt.Errorf("sqlite: read %s: %w", f, err)
		}
		tx, err := d.db.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlite: begin tx for %s: %w", f, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite: apply %s: %w", f, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at_ms) VALUES(?, strftime('%s','now')*1000)`,
			f); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite: record %s: %w", f, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlite: commit %s: %w", f, err)
		}
	}
	return nil
}

// loadAppliedMigrations reads the schema_migrations table and
// returns a set of versions already applied. Factored out of
// migrate so the rows.Close lives on a defer (sqlclosecheck) and
// rows.Err() can be checked after the loop without obscuring the
// migrate flow.
func (d *DB) loadAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("sqlite: scan applied: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate applied: %w", err)
	}
	return applied, nil
}

// mapSQLErr converts common sql errors into domain sentinels.
func mapSQLErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return domain.NewNotFoundError("NOT_FOUND", err.Error())
	case isUniqueViolation(err):
		return domain.NewConflictError("ALREADY_EXISTS", err.Error())
	default:
		return err
	}
}

func isUniqueViolation(err error) bool {
	// SQLite emits the same human-readable message regardless of
	// driver, so substring match works across mattn and modernc.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
