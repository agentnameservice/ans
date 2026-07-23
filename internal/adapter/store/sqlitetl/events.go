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

	"github.com/agentnameservice/ans/internal/tl/event"
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
//
// AgentID and IdentityID are the two read-index keys over the single
// log: agent events carry AgentID (IdentityID empty), identity events
// carry IdentityID (AgentID empty). "Stream" means nothing more than
// filtering this table by one of those keys.
type EventRecord struct {
	ID            int64  `db:"id"`
	LeafIndex     uint64 `db:"leaf_index"`
	LeafHashHex   string `db:"leaf_hash"`
	EventHashHex  string `db:"event_hash"`
	LogID         string `db:"log_id"`
	AgentID       string `db:"agent_id"`
	AnsName       string `db:"ans_name"`
	AgentFQDN     string `db:"agent_fqdn"`
	IdentityID    string `db:"identity_id"`
	EventType     string `db:"event_type"`
	SchemaVersion string `db:"schema_version"`
	RawEvent      string `db:"raw_event"`
	CreatedAtMs   int64  `db:"created_at_ms"`
}

// eventCols is the shared SELECT column list. identity_id is nullable
// on disk (NULL for agent events); COALESCE keeps the Go-side scan a
// plain string.
const eventCols = `id, leaf_index, leaf_hash, event_hash, log_id,
       agent_id, ans_name, agent_fqdn, event_type,
       schema_version, raw_event, created_at_ms,
       COALESCE(identity_id, '') AS identity_id`

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

// LinkState is the latest link/unlink fact for one (identity, agent)
// pair, computed from the tl_identity_event_agents read-join index. A
// link is live when EventType == IDENTITY_LINKED; whether it is
// *effective* additionally depends on the identity's and agent's
// current stream state, which the service layer joins in.
type LinkState struct {
	IdentityID  string `db:"identity_id"`
	AnsID       string `db:"ans_id"`
	LeafIndex   uint64 `db:"leaf_index"`
	EventType   string `db:"event_type"`
	CreatedAtMs int64  `db:"created_at_ms"`
}

// eventTypeIdentityLinked mirrors identityevent.TypeIdentityLinked
// without importing the event package for one comparison string.
const eventTypeIdentityLinked = "IDENTITY_LINKED"

// Linked reports whether the latest event for the pair is a link.
func (l *LinkState) Linked() bool { return l.EventType == eventTypeIdentityLinked }

// identityIndexed is the optional capability an envelope exposes when
// it should be indexed on the identity stream. The identity envelope
// implements it; agent envelopes (V1/V2) don't, and simply land with
// a NULL identity_id. Discovering the capability by type assertion
// keeps event.View frozen for existing implementers.
type identityIndexed interface {
	IdentityID() string
	LinkedAgentIDs() []string
}

// EventStore persists event records. Mirrors the reference
// EventStorage.StoreEvent / GetLatestRecordByAgentID / GetRecordsByAgentID /
// GetEventByLeafIndex surface, extended with the identity read index.
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
// Takes an event.View so every envelope shape lands through the same
// persistence path; the `schema_version` column holds `env.Version()`
// for downstream read handlers to echo back.
//
// Identity envelopes (discovered via the identityIndexed capability)
// additionally fan their linked-agent ids into the
// tl_identity_event_agents read-join index, atomically with the event
// row — a link event whose index rows were lost would silently hide
// the association from every agent-side read.
func (s *EventStore) StoreEvent(
	ctx context.Context,
	leafIndex uint64,
	leafHash [32]byte,
	innerEventHash string,
	env event.View,
	canonicalEnvelope []byte,
) (*EventRecord, error) {
	identityID := ""
	var linkedAgents []string
	if iv, ok := env.(identityIndexed); ok {
		identityID = iv.IdentityID()
		linkedAgents = iv.LinkedAgentIDs()
	}

	tx, err := s.db.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	now := nowMs()
	const q = `
        INSERT INTO tl_events(
            leaf_index, leaf_hash, event_hash, log_id,
            agent_id, ans_name, agent_fqdn, event_type,
            schema_version, raw_event, created_at_ms, identity_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`
	if _, err := tx.ExecContext(ctx, q,
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
		now,
		identityID,
	); err != nil {
		return nil, mapSQLErr(err)
	}

	if identityID != "" && len(linkedAgents) > 0 {
		const fq = `
            INSERT INTO tl_identity_event_agents(
                leaf_index, identity_id, ans_id, event_type, created_at_ms
            ) VALUES (?, ?, ?, ?, ?)`
		for _, ansID := range linkedAgents {
			if _, err := tx.ExecContext(ctx, fq, leafIndex, identityID, ansID, env.EventType(), now); err != nil {
				return nil, mapSQLErr(err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, mapSQLErr(err)
	}
	return s.GetEventByLeafIndex(ctx, leafIndex)
}

// GetEventByLeafIndex returns the event at the given leaf.
func (s *EventStore) GetEventByLeafIndex(ctx context.Context, index uint64) (*EventRecord, error) {
	var r EventRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT `+eventCols+` FROM tl_events WHERE leaf_index = ?`, index)
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
		err = s.db.db.GetContext(ctx, &r,
			`SELECT `+eventCols+`
            FROM tl_events
            WHERE agent_id = ? AND leaf_index < ?
            ORDER BY leaf_index DESC LIMIT 1`, agentID, maxLeafIndex)
	} else {
		err = s.db.db.GetContext(ctx, &r,
			`SELECT `+eventCols+`
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
	limit, offset = clampPage(limit, offset)
	var rows []*EventRecord
	var err error
	if maxLeafIndex > 0 {
		err = s.db.db.SelectContext(ctx, &rows,
			`SELECT `+eventCols+`
            FROM tl_events
            WHERE agent_id = ? AND leaf_index < ?
            ORDER BY leaf_index DESC LIMIT ? OFFSET ?`,
			agentID, maxLeafIndex, limit, offset)
	} else {
		err = s.db.db.SelectContext(ctx, &rows,
			`SELECT `+eventCols+`
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

// GetLatestByIdentityID returns the newest event on an identity's
// stream — the read index over the single log keyed by identity_id.
func (s *EventStore) GetLatestByIdentityID(ctx context.Context, identityID string) (*EventRecord, error) {
	var r EventRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT `+eventCols+`
        FROM tl_events
        WHERE identity_id = ?
        ORDER BY leaf_index DESC LIMIT 1`, identityID)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return &r, nil
}

// GetByIdentityID returns paginated events for an identity, newest first.
func (s *EventStore) GetByIdentityID(
	ctx context.Context,
	identityID string,
	limit, offset int,
) ([]*EventRecord, error) {
	limit, offset = clampPage(limit, offset)
	var rows []*EventRecord
	err := s.db.db.SelectContext(ctx, &rows,
		`SELECT `+eventCols+`
        FROM tl_events
        WHERE identity_id = ?
        ORDER BY leaf_index DESC LIMIT ? OFFSET ?`,
		identityID, limit, offset)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// GetLatestProofByIdentityID returns the newest *proof* event
// (IDENTITY_VERIFIED / IDENTITY_UPDATED) on an identity's stream —
// the event carrying the current proven key set. Link events sit on
// the same stream but carry no keys; badge joins need the proof.
func (s *EventStore) GetLatestProofByIdentityID(ctx context.Context, identityID string) (*EventRecord, error) {
	var r EventRecord
	err := s.db.db.GetContext(ctx, &r,
		`SELECT `+eventCols+`
        FROM tl_events
        WHERE identity_id = ?
          AND event_type IN ('IDENTITY_VERIFIED', 'IDENTITY_UPDATED')
        ORDER BY leaf_index DESC LIMIT 1`, identityID)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return &r, nil
}

// HasIdentityRevoked reports whether the identity's stream contains
// an IDENTITY_REVOKED event. Revocation is terminal at READ time
// regardless of stream tail order: a racing operation's event can
// land after the revocation leaf (the RA's seal spans a network
// round trip), and a late leaf must never resurrect a revoked
// identity on the public surface.
func (s *EventStore) HasIdentityRevoked(ctx context.Context, identityID string) (bool, error) {
	var one int
	err := s.db.db.GetContext(ctx, &one, `
        SELECT 1 FROM tl_events
        WHERE identity_id = ? AND event_type = 'IDENTITY_REVOKED'
        LIMIT 1`, identityID)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, err
	}
}

// LinkStatesByAgent returns, for one agent, the latest link/unlink
// fact per identity that ever named it — the badge-join input. Rows
// where Linked() is true are the agent's live links.
func (s *EventStore) LinkStatesByAgent(ctx context.Context, ansID string) ([]*LinkState, error) {
	var rows []*LinkState
	err := s.db.db.SelectContext(ctx, &rows, `
        SELECT a.identity_id, a.ans_id, a.leaf_index, a.event_type, a.created_at_ms
        FROM tl_identity_event_agents a
        JOIN (
            SELECT identity_id, MAX(leaf_index) AS max_leaf
            FROM tl_identity_event_agents
            WHERE ans_id = ?
            GROUP BY identity_id
        ) m ON a.identity_id = m.identity_id AND a.leaf_index = m.max_leaf
        WHERE a.ans_id = ?
        ORDER BY a.leaf_index DESC`, ansID, ansID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// LinkStatesByIdentity returns, for one identity, the latest
// link/unlink fact per agent it ever named — the reverse join.
func (s *EventStore) LinkStatesByIdentity(ctx context.Context, identityID string) ([]*LinkState, error) {
	var rows []*LinkState
	err := s.db.db.SelectContext(ctx, &rows, `
        SELECT a.identity_id, a.ans_id, a.leaf_index, a.event_type, a.created_at_ms
        FROM tl_identity_event_agents a
        JOIN (
            SELECT ans_id, MAX(leaf_index) AS max_leaf
            FROM tl_identity_event_agents
            WHERE identity_id = ?
            GROUP BY ans_id
        ) m ON a.ans_id = m.ans_id AND a.leaf_index = m.max_leaf
        WHERE a.identity_id = ?
        ORDER BY a.leaf_index DESC`, identityID, identityID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// LinkEventsByAgent returns the link/unlink events that ever named
// this agent, newest first — the per-agent association history,
// served in the standard audit envelope by the handler.
func (s *EventStore) LinkEventsByAgent(
	ctx context.Context,
	ansID string,
	limit, offset int,
) ([]*EventRecord, error) {
	limit, offset = clampPage(limit, offset)
	var rows []*EventRecord
	err := s.db.db.SelectContext(ctx, &rows,
		`SELECT `+eventColsPrefixed+`
        FROM tl_events e
        JOIN tl_identity_event_agents a ON a.leaf_index = e.leaf_index
        WHERE a.ans_id = ?
        ORDER BY e.leaf_index DESC LIMIT ? OFFSET ?`,
		ansID, limit, offset)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// eventColsPrefixed is eventCols with an `e.` table alias for joined
// queries.
const eventColsPrefixed = `e.id, e.leaf_index, e.leaf_hash, e.event_hash, e.log_id,
       e.agent_id, e.ans_name, e.agent_fqdn, e.event_type,
       e.schema_version, e.raw_event, e.created_at_ms,
       COALESCE(e.identity_id, '') AS identity_id`

// clampPage normalizes pagination inputs.
func clampPage(limit, offset int) (int, int) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
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
