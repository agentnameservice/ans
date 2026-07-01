// Package sqlitefinder is the SQLite FTS5-backed implementation of the
// Finder's index.Catalog port. It holds the discovery catalog the Finder
// serves: one row per projected entry, a full-text index over the
// searchable fields, normalized side-tables for the multi-valued filter
// and facet dimensions, and a singleton poll cursor.
//
// The adapter uses modernc.org/sqlite (a pure-Go SQLite with FTS5
// compiled in), so the binary cross-compiles without CGO. Schema
// migrations are embedded and applied on Open.
//
// Connection pool: SetMaxOpenConns(1) pins the store to a SINGLE
// connection, so every access — the poller's writes and search/explore's
// reads — serializes through it, matching the rest of the repo's SQLite
// adapters. This is the simple, deadlock-free default for a low-volume
// local index; it does NOT give reader/writer concurrency (WAL is enabled
// but irrelevant with one connection). A higher-throughput deployment
// that needs concurrent reads while the poller writes would raise the
// read-pool size and keep a single writer — a separate two-pool topology
// noted as a deferred follow-up, not wired here.
package sqlitefinder

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // driver

	"github.com/godaddy/ans/internal/finder/index"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the SQLite-backed catalog index. Construct it with Open; it
// satisfies index.Catalog.
type Store struct {
	db *sqlx.DB
}

// compile-time assertion that Store implements the index port.
var _ index.Catalog = (*Store)(nil)

// Open creates or opens the Finder index database at path and applies
// pending migrations. path == ":memory:" yields an in-memory DB for
// tests.
func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("sqlitefinder: create dir %s: %w", dir, err)
			}
		}
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if path == ":memory:" {
		dsn = path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	db, err := sqlx.ConnectContext(ctx, "sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitefinder: connect: %w", err)
	}
	// Single writer inside the process (the poller). WAL keeps concurrent
	// search/explore readers from blocking on it.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version       TEXT PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        )`); err != nil {
		return fmt.Errorf("sqlitefinder: create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlitefinder: read migrations: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied, err := s.loadAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, f := range files {
		if _, ok := applied[f]; ok {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return fmt.Errorf("sqlitefinder: read %s: %w", f, err)
		}
		tx, err := s.db.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlitefinder: begin tx for %s: %w", f, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlitefinder: apply %s: %w", f, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at_ms)
             VALUES(?, strftime('%s','now')*1000)`, f); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlitefinder: record %s: %w", f, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlitefinder: commit %s: %w", f, err)
		}
	}
	return nil
}

// loadAppliedMigrations reads the schema_migrations table into a set.
// Factored out so rows.Close lives on a defer and rows.Err is checked
// after the loop.
func (s *Store) loadAppliedMigrations(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlitefinder: query applied: %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("sqlitefinder: scan applied: %w", err)
		}
		applied[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitefinder: iterate applied: %w", err)
	}
	return applied, nil
}
