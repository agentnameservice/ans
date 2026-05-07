package sqlitetl

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// CheckpointRecord is a persisted checkpoint row.
type CheckpointRecord struct {
	ID            int64  `db:"id"`
	TreeSize      uint64 `db:"tree_size"`
	TreeHashHex   string `db:"tree_hash_hex"`
	CheckpointRaw string `db:"checkpoint_raw"`
	Origin        string `db:"origin"`
	CreatedAtMs   int64  `db:"created_at_ms"`
}

// CreatedAt returns the checkpoint creation time in UTC.
func (r *CheckpointRecord) CreatedAt() time.Time { return time.UnixMilli(r.CreatedAtMs).UTC() }

// CheckpointStore persists checkpoint history. Tessera holds the current
// checkpoint in its storage directory; this table exists for consistency
// proofs between checkpoints and for administrative audit.
type CheckpointStore struct{ db *DB }

// NewCheckpointStore returns a new CheckpointStore.
func NewCheckpointStore(db *DB) *CheckpointStore { return &CheckpointStore{db: db} }

// Store persists a checkpoint. If a row with the same tree_hash already
// exists the call is a no-op (INSERT OR IGNORE semantics), matching the
// reference's duplicate-safe behavior.
func (s *CheckpointStore) Store(
	ctx context.Context,
	treeSize uint64,
	treeRoot []byte,
	checkpointRaw []byte,
	origin string,
) error {
	treeHashHex := hex.EncodeToString(treeRoot)
	const q = `
        INSERT OR IGNORE INTO tl_checkpoints(
            tree_size, tree_hash_hex, checkpoint_raw, origin, created_at_ms
        ) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.db.ExecContext(ctx, q,
		treeSize, treeHashHex, string(checkpointRaw), origin, nowMs())
	return mapSQLErr(err)
}

// Latest returns the newest persisted checkpoint.
func (s *CheckpointStore) Latest(ctx context.Context) (*CheckpointRecord, error) {
	var r CheckpointRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT id, tree_size, tree_hash_hex, checkpoint_raw, origin, created_at_ms
         FROM tl_checkpoints ORDER BY tree_size DESC LIMIT 1`)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return &r, nil
}

// ByTreeSizeAtLeast returns the smallest persisted checkpoint with
// tree_size >= target. Used when clients request a proof against a
// specific size and we need a signed head that covers it.
func (s *CheckpointStore) ByTreeSizeAtLeast(ctx context.Context, target uint64) (*CheckpointRecord, error) {
	var r CheckpointRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT id, tree_size, tree_hash_hex, checkpoint_raw, origin, created_at_ms
         FROM tl_checkpoints WHERE tree_size >= ?
         ORDER BY tree_size ASC LIMIT 1`, target)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // (nil, nil) signals "no checkpoint covers this tree size yet"
		}
		return nil, err
	}
	return &r, nil
}

// Count returns the number of checkpoints matching the same filter
// shape as List. The handler uses it to populate the paginated
// response's `total` field without a second round-trip per-request.
func (s *CheckpointStore) Count(
	ctx context.Context,
	fromSize, toSize *uint64,
	since *time.Time,
) (int64, error) {
	q := `SELECT COUNT(*) FROM tl_checkpoints WHERE 1=1`
	var args []any
	if fromSize != nil {
		q += " AND tree_size >= ?"
		args = append(args, *fromSize)
	}
	if toSize != nil {
		q += " AND tree_size <= ?"
		args = append(args, *toSize)
	}
	if since != nil {
		q += " AND created_at_ms >= ?"
		args = append(args, since.UnixMilli())
	}
	var total int64
	if err := s.db.db.GetContext(ctx, &total, q, args...); err != nil {
		return 0, err
	}
	return total, nil
}

// List returns paginated checkpoints with optional size and time filters.
func (s *CheckpointStore) List(
	ctx context.Context,
	limit, offset int,
	fromSize, toSize *uint64,
	since *time.Time,
	order string,
) ([]*CheckpointRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT id, tree_size, tree_hash_hex, checkpoint_raw, origin, created_at_ms
         FROM tl_checkpoints WHERE 1=1`
	var args []any
	if fromSize != nil {
		q += " AND tree_size >= ?"
		args = append(args, *fromSize)
	}
	if toSize != nil {
		q += " AND tree_size <= ?"
		args = append(args, *toSize)
	}
	if since != nil {
		q += " AND created_at_ms >= ?"
		args = append(args, since.UnixMilli())
	}
	dir := "DESC"
	if strings.EqualFold(order, "asc") {
		dir = "ASC"
	}
	q += " ORDER BY tree_size " + dir + " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	var rows []*CheckpointRecord
	err := s.db.db.SelectContext(ctx, &rows, q, args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}
