package sqlitetl

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/tl/event"
)

// EventRecord is the stored event row returned to services.
//
// Two hash columns, each answering a different question:
//
//   - LeafHashHex  — RFC 6962 §2.1 leaf hash of the full envelope,
//     matches Tessera's internal leaf. Used by an
//     inclusion-proof verifier walking to the root.
//   - EventHashHex — SHA-256 of the JCS-canonical inner-producer-event
//     bytes. UNIQUE — the table rejects retries with
//     the same inner event content.
type EventRecord struct {
	ID            int64  `db:"id"`
	LeafIndex     uint64 `db:"leaf_index"`
	LeafHashHex   string `db:"leaf_hash"`
	EventHashHex  string `db:"event_hash"`
	LogID         string `db:"log_id"`
	AgentID       string `db:"agent_id"`
	AnsName       string `db:"ans_name"`
	AgentFQDN     string `db:"agent_fqdn"`
	EventType     string `db:"event_type"`
	SchemaVersion string `db:"schema_version"`
	RawEvent      string `db:"raw_event"`
	CreatedAtMs   int64  `db:"created_at_ms"`
}

// CreatedAt returns the event creation time in UTC.
func (r *EventRecord) CreatedAt() time.Time { return time.UnixMilli(r.CreatedAtMs).UTC() }

// Envelope parses the stored raw_event JSON back into an event.Envelope.
func (r *EventRecord) Envelope() (*event.Envelope, error) {
	var env event.Envelope
	if err := json.Unmarshal([]byte(r.RawEvent), &env); err != nil {
		return nil, fmt.Errorf("sqlite_tl: parse raw_event: %w", err)
	}
	return &env, nil
}

// LeafHashBytes returns the 32-byte RFC 6962 leaf hash.
func (r *EventRecord) LeafHashBytes() ([32]byte, error) {
	raw, err := hex.DecodeString(r.LeafHashHex)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, errors.New("sqlite_tl: invalid leaf hash hex")
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

// EventStore persists event records. Mirrors the reference
// EventStorage.StoreEvent / GetLatestRecordByAgentID / GetRecordsByAgentID /
// GetEventByLeafIndex surface.
type EventStore struct{ db *DB }

// NewEventStore returns a new SQLite-backed event store.
func NewEventStore(db *DB) *EventStore { return &EventStore{db: db} }

// ComputeEventHash returns the dedup hash for an inner producer event:
// SHA-256 over the JCS-canonical bytes of the event (not the envelope).
//
// Exposed so the LogService and the producer-sig verifier can agree on
// the hash without re-serializing in each place.
func ComputeEventHash(innerCanonical []byte) string {
	sum := sha256.Sum256(innerCanonical)
	return hex.EncodeToString(sum[:])
}

// StoreEvent persists a freshly-appended event. Returns a domain
// conflict error if event_hash already exists (idempotent retry).
// Takes an event.View so both V1 and V2 envelopes land through the
// same persistence path; the `schema_version` column holds
// `env.Version()` for downstream read handlers to echo back in the
// TransparencyLog response.
func (s *EventStore) StoreEvent(
	ctx context.Context,
	leafIndex uint64,
	leafHash [32]byte,
	innerEventHash string,
	env event.View,
	canonicalEnvelope []byte,
) (*EventRecord, error) {
	const q = `
        INSERT INTO tl_events(
            leaf_index, leaf_hash, event_hash, log_id,
            agent_id, ans_name, agent_fqdn, event_type,
            schema_version, raw_event, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.db.ExecContext(ctx, q,
		leafIndex,
		hex.EncodeToString(leafHash[:]),
		innerEventHash,
		env.LogID(),
		env.AgentID(),
		env.AnsName(),
		env.AgentFQDN(),
		env.EventType(),
		env.Version(),
		string(canonicalEnvelope),
		nowMs(),
	)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return s.GetEventByLeafIndex(ctx, leafIndex)
}

// GetEventByLeafIndex returns the event at the given leaf.
func (s *EventStore) GetEventByLeafIndex(ctx context.Context, index uint64) (*EventRecord, error) {
	var r EventRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT id, leaf_index, leaf_hash, event_hash, log_id,
                agent_id, ans_name, agent_fqdn, event_type,
                schema_version, raw_event, created_at_ms
         FROM tl_events WHERE leaf_index = ?`, index)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return &r, nil
}

// GetLatestByAgentID returns the newest event for an agent.
// If maxLeafIndex > 0 the result is bounded to leaves strictly below it
// (matches the reference's consistency-with-checkpoint pattern).
func (s *EventStore) GetLatestByAgentID(ctx context.Context, agentID string, maxLeafIndex uint64) (*EventRecord, error) {
	var r EventRecord
	var err error
	if maxLeafIndex > 0 {
		err = s.db.db.GetContext(ctx, &r, `
            SELECT id, leaf_index, leaf_hash, event_hash, log_id,
                   agent_id, ans_name, agent_fqdn, event_type,
                   schema_version, raw_event, created_at_ms
            FROM tl_events
            WHERE agent_id = ? AND leaf_index < ?
            ORDER BY leaf_index DESC LIMIT 1`, agentID, maxLeafIndex)
	} else {
		err = s.db.db.GetContext(ctx, &r, `
            SELECT id, leaf_index, leaf_hash, event_hash, log_id,
                   agent_id, ans_name, agent_fqdn, event_type,
                   schema_version, raw_event, created_at_ms
            FROM tl_events
            WHERE agent_id = ?
            ORDER BY leaf_index DESC LIMIT 1`, agentID)
	}
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return &r, nil
}

// GetByAgentID returns paginated events for an agent, newest first.
func (s *EventStore) GetByAgentID(
	ctx context.Context,
	agentID string,
	limit, offset int,
	maxLeafIndex uint64,
) ([]*EventRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var rows []*EventRecord
	var err error
	if maxLeafIndex > 0 {
		err = s.db.db.SelectContext(ctx, &rows, `
            SELECT id, leaf_index, leaf_hash, event_hash, log_id,
                   agent_id, ans_name, agent_fqdn, event_type,
                   schema_version, raw_event, created_at_ms
            FROM tl_events
            WHERE agent_id = ? AND leaf_index < ?
            ORDER BY leaf_index DESC LIMIT ? OFFSET ?`,
			agentID, maxLeafIndex, limit, offset)
	} else {
		err = s.db.db.SelectContext(ctx, &rows, `
            SELECT id, leaf_index, leaf_hash, event_hash, log_id,
                   agent_id, ans_name, agent_fqdn, event_type,
                   schema_version, raw_event, created_at_ms
            FROM tl_events
            WHERE agent_id = ?
            ORDER BY leaf_index DESC LIMIT ? OFFSET ?`,
			agentID, limit, offset)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// ExistsByEventHash returns (true, leafIndex) if an event with the
// given content hash has already been stored, enabling idempotent
// retries at the service layer. The UNIQUE constraint on event_hash
// also enforces this at insert time as a belt-and-braces guard.
func (s *EventStore) ExistsByEventHash(ctx context.Context, eventHashHex string) (bool, uint64, error) {
	var leafIdx sql.NullInt64
	err := s.db.db.GetContext(ctx, &leafIdx,
		`SELECT leaf_index FROM tl_events WHERE event_hash = ?`, eventHashHex)
	switch {
	case err == nil && leafIdx.Valid:
		// leaf_index is non-negative by construction (Tessera issues
		// monotonically increasing 0-based indexes); int64 → uint64
		// is safe.
		return true, uint64(leafIdx.Int64), nil //nolint:gosec // G115: leaf index always ≥ 0
	case errors.Is(err, sql.ErrNoRows):
		return false, 0, nil
	default:
		return false, 0, err
	}
}
