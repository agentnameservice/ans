package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// txKey is the unexported context-key under which Run stashes the
// active transaction. Stores call db.extx(ctx) to retrieve it; the
// type is private so no caller outside this package can extract or
// inject the raw `*sqlx.Tx`. That keeps the port boundary clean —
// the service layer only ever sees `port.UnitOfWork.Run`.
type txKey struct{}

// Run implements port.UnitOfWork. It begins a transaction, threads
// it through fn's context, and commits or rolls back depending on
// fn's return.
//
// Rollback errors are wrapped together with the original error so
// neither is lost — a rollback failure usually points at a deeper
// problem (deadlock detector firing, connection lost) and silently
// dropping it would mask the real diagnostic.
//
// Implementation note: SQLite serializes writes inside the process
// (we cap MaxOpenConns at 1 in `Open`), so opening a transaction
// also serializes other writers against the same DB. Transactions
// are expected to be short-lived for that reason.
func (d *DB) Run(ctx context.Context, fn func(ctx context.Context) error) (errR error) {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin tx: %w", err)
	}
	defer func() {
		if errR != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				errR = fmt.Errorf("%w; rollback: %w", errR, rbErr)
			}
		}
	}()
	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
}

// sqlxConn is the narrow subset of sqlx methods our stores actually
// use. Both `*sqlx.DB` and `*sqlx.Tx` satisfy it, so stores can
// route every read/write through `extx(ctx)` and pick up an active
// transaction transparently.
type sqlxConn interface {
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryxContext(ctx context.Context, query string, args ...any) (*sqlx.Rows, error)
}

// extx returns the active transaction from ctx, or the underlying
// sqlx.DB when no transaction is in scope. Stores call this for
// every query so they automatically participate in a UnitOfWork.Run
// when the caller wraps them, and fall back to autocommit otherwise.
func (d *DB) extx(ctx context.Context) sqlxConn {
	if tx, ok := ctx.Value(txKey{}).(*sqlx.Tx); ok {
		return tx
	}
	return d.db
}
