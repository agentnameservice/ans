package sqlite

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// OutboxEvent represents a row from the outbox_events table.
// It is not a port type (the outbox is an internal adapter concept)
// but it is used by the RA→TL client worker.
//
// SchemaVersion names the envelope schema the RA serialized the
// inner-event payload for ("V1" or "V2"). The worker uses it to
// route to the matching TL ingest lane. Both the column and this
// field were added together (migration 003) so the worker never
// sees an empty value.
type OutboxEvent struct {
	ID            int64
	EventType     string
	AgentID       string
	SchemaVersion string
	PayloadJSON   []byte
	Attempts      int
	LastError     string
	NextAttemptAt time.Time
	SentAt        time.Time
	CreatedAt     time.Time
}

// OutboxStore manages the outbox_events table used for durable RA→TL
// delivery.
type OutboxStore struct{ db *DB }

// NewOutboxStore returns a new OutboxStore.
func NewOutboxStore(db *DB) *OutboxStore { return &OutboxStore{db: db} }

// Enqueue appends a new outbox event. When the caller wraps this
// call inside `port.UnitOfWork.Run`, the row is written through the
// active transaction (via the context-threaded tx in `extx`) and
// commits or rolls back atomically with whatever domain-state writes
// preceded it — that's how we guarantee at-least-once delivery
// without a dual-write window.
//
// schemaVersion must be "V1" or "V2"; the worker reads this value
// to pick the matching TL ingest lane. An empty value is rejected.
func (s *OutboxStore) Enqueue(
	ctx context.Context,
	eventType, agentID, schemaVersion string,
	payload []byte,
	earliestAttempt time.Time,
) (int64, error) {
	if len(payload) == 0 {
		return 0, errors.New("sqlite/outbox: payload is empty")
	}
	switch schemaVersion {
	case "V1", "V2":
	default:
		return 0, fmt.Errorf("sqlite/outbox: invalid schemaVersion %q (want V1 or V2)", schemaVersion)
	}
	const q = `
        INSERT INTO outbox_events(event_type, agent_id, schema_version, payload_json,
            next_attempt_at_ms, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?)`
	now := time.Now().UnixMilli()
	res, err := s.db.extx(ctx).ExecContext(ctx, q, eventType, agentID, schemaVersion, string(payload),
		earliestAttempt.UnixMilli(), now)
	if err != nil {
		return 0, mapSQLErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Claim returns up to batchSize pending outbox events whose
// next_attempt_at_ms has passed. Callers process each event and then
// call MarkSent or MarkFailed. There is no explicit lease — we rely on
// the single-writer SQLite setup.
func (s *OutboxStore) Claim(ctx context.Context, batchSize int) ([]OutboxEvent, error) {
	if batchSize <= 0 {
		batchSize = 10
	}
	const q = `
        SELECT id, event_type, agent_id, schema_version, payload_json, attempts,
               COALESCE(last_error, '') AS last_error,
               next_attempt_at_ms, created_at_ms
        FROM outbox_events
        WHERE sent_at_ms IS NULL AND next_attempt_at_ms <= ?
        ORDER BY id ASC
        LIMIT ?`
	rows, err := s.db.db.QueryContext(ctx, q, time.Now().UnixMilli(), batchSize)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	defer rows.Close()

	var out []OutboxEvent
	for rows.Next() {
		var e OutboxEvent
		var nextMs, createdMs int64
		var payload string
		if err := rows.Scan(&e.ID, &e.EventType, &e.AgentID, &e.SchemaVersion, &payload, &e.Attempts,
			&e.LastError, &nextMs, &createdMs); err != nil {
			return nil, err
		}
		e.PayloadJSON = []byte(payload)
		e.NextAttemptAt = msToTime(nextMs)
		e.CreatedAt = msToTime(createdMs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkSent records that the event was successfully delivered, writing
// the TL-assigned logId and the send timestamp in a single UPDATE so a
// row never appears delivered without its logId. The agent-events feed
// gates on both columns being non-NULL, so this atomicity is what makes
// "row is in the feed" imply "row has a resolvable receipt".
//
// logID is the value the TL echoed in its ingest response
// (AppendResult.LogID). It is also echoed on idempotent duplicate
// retries, so a re-delivered row records the same logId.
func (s *OutboxStore) MarkSent(ctx context.Context, id int64, logID string) error {
	_, err := s.db.db.ExecContext(ctx,
		`UPDATE outbox_events SET sent_at_ms = ?, log_id = ? WHERE id = ?`,
		time.Now().UnixMilli(), logID, id)
	return mapSQLErr(err)
}

// MarkFailed bumps the attempt counter and schedules the next retry
// using exponential backoff capped at maxDelay.
func (s *OutboxStore) MarkFailed(ctx context.Context, id int64, attempts int, lastError string, maxDelay time.Duration) error {
	// base 1s, doubles each attempt, capped.
	delay := time.Duration(1<<minInt(attempts, 10)) * time.Second
	if delay > maxDelay {
		delay = maxDelay
	}
	next := time.Now().Add(delay)
	const q = `
        UPDATE outbox_events SET
            attempts = ?, last_error = ?, next_attempt_at_ms = ?
        WHERE id = ?`
	_, err := s.db.db.ExecContext(ctx, q, attempts, lastError, next.UnixMilli(), id)
	return mapSQLErr(err)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
