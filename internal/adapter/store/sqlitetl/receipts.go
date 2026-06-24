package sqlitetl

import (
	"context"
	"database/sql"
	"errors"
)

// ReceiptRecord is a stored receipt row.
type ReceiptRecord struct {
	ID          int64  `db:"id"`
	LeafIndex   uint64 `db:"leaf_index"`
	AgentID     string `db:"agent_id"`
	TreeSize    uint64 `db:"tree_size"`
	ReceiptBlob []byte `db:"receipt_blob"`
	CreatedAtMs int64  `db:"created_at_ms"`
}

// ReceiptStore caches pre-generated receipts keyed by (leaf_index, tree_size).
// Receipts are relatively expensive to build (proof walk + signing) and
// immutable once produced, so caching amortizes the cost across reads.
type ReceiptStore struct{ db *DB }

// NewReceiptStore returns a new ReceiptStore.
func NewReceiptStore(db *DB) *ReceiptStore { return &ReceiptStore{db: db} }

// Store upserts a receipt. Duplicate (leaf_index, tree_size) pairs are
// silently ignored since the receipt would be identical.
func (s *ReceiptStore) Store(
	ctx context.Context,
	leafIndex uint64,
	agentID string,
	treeSize uint64,
	receipt []byte,
) error {
	const q = `
        INSERT OR IGNORE INTO tl_receipts(
            leaf_index, agent_id, tree_size, receipt_blob, created_at_ms
        ) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.db.ExecContext(ctx, q, leafIndex, agentID, treeSize, receipt, nowMs())
	return mapSQLErr(err)
}

// FindByLeafIndex returns the cached receipt for a specific
// (leaf_index, tree_size) pair — the table's natural UNIQUE key — or
// (nil, nil) if no cached receipt exists. The pair fully determines
// the receipt's payload (same event bytes + same inclusion proof),
// and unlike an agent-keyed lookup it works identically for agent
// and identity subjects (identity events carry no agent id).
func (s *ReceiptStore) FindByLeafIndex(
	ctx context.Context,
	leafIndex uint64,
	treeSize uint64,
) (*ReceiptRecord, error) {
	var r ReceiptRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT id, leaf_index, agent_id, tree_size, receipt_blob, created_at_ms
         FROM tl_receipts
         WHERE leaf_index = ? AND tree_size = ?`, leafIndex, treeSize)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // (nil, nil) signals "no cached receipt for this tree size"
		}
		return nil, err
	}
	return &r, nil
}
