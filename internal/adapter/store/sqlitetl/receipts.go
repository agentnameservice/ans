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

// FindByAgentID returns the cached receipt for an agent's latest
// event at the given tree size, or (nil, nil) if no cached receipt
// exists. Unlike GetLatestByAgentID this scopes to a specific tree
// size so the ReceiptService can key its cache on (agent,
// treeSize) rather than (leafIndex, treeSize) — agents can have
// multiple events in the log but the receipt we want is always the
// latest one covered by the current checkpoint.
func (s *ReceiptStore) FindByAgentID(
	ctx context.Context,
	agentID string,
	treeSize uint64,
) (*ReceiptRecord, error) {
	var r ReceiptRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT id, leaf_index, agent_id, tree_size, receipt_blob, created_at_ms
         FROM tl_receipts
         WHERE agent_id = ? AND tree_size = ?
         ORDER BY leaf_index DESC LIMIT 1`, agentID, treeSize)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // (nil, nil) signals "no cached receipt for this tree size"
		}
		return nil, err
	}
	return &r, nil
}
