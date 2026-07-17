package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/port"
)

// FeedStore serves the agent-events feed read model: delivered,
// TL-logged outbox rows joined with their registration and endpoint
// rows, bounded by a retention window and a cursor.
//
// It implements port.FeedReader. The feed is read-only and runs
// outside any unit of work, so it queries the database handle
// directly rather than the context-threaded tx.
//
// Gating invariant: only rows with sent_at_ms IS NOT NULL AND
// log_id IS NOT NULL are visible. That is what makes "in the feed"
// imply "sealed in the log, receipt resolvable from logId". A row that
// the outbox worker has not yet delivered (or delivered before
// migration 006, hence with a NULL log_id) is invisible.

// feedDefaultLimit guards against a non-positive limit reaching the
// query. The events service already clamps the page size to the
// feed's [1, max] range, so this is a defensive floor only.
const feedDefaultLimit = 100

type FeedStore struct {
	db        *DB
	retention time.Duration
	clock     func() time.Time
}

// NewFeedStore constructs a FeedStore. retention bounds how far back
// the feed serves, anchored on each row's enqueue time (created_at_ms);
// rows older than now-retention are excluded. A non-positive retention
// is treated as "no lower bound" (serve everything delivered), which is
// only sensible for tests — production wires a real window from config.
func NewFeedStore(db *DB, retention time.Duration) *FeedStore {
	return &FeedStore{db: db, retention: retention, clock: time.Now}
}

// ReadFeed returns delivered, logged outbox rows within the retention
// window, ordered by outbox id ascending, starting after the cursor.
//
// Cursor semantics: q.AfterLogID is resolved to the outbox id of the
// row that carries that logId; rows with a strictly greater id are
// returned. An empty cursor, or a cursor that resolves to no row
// (unknown id, or a row that has aged out of the retention window),
// starts from the oldest retained row. Retention makes "expired" and
// "never existed" indistinguishable here by design — both fall back to
// the oldest retained row rather than erroring.
func (s *FeedStore) ReadFeed(ctx context.Context, q port.FeedQuery) ([]port.FeedRow, error) {
	// The OSS RA has no provider concept. A provider-scoped request
	// therefore matches nothing — return an empty page rather than
	// ignoring the filter (which would silently widen the result).
	if q.ProviderFilter != "" {
		return []port.FeedRow{}, nil
	}

	limit := q.Limit
	if limit <= 0 {
		limit = feedDefaultLimit
	}

	retentionFloorMs := s.retentionFloorMs()

	afterID, err := s.resolveCursor(ctx, q.AfterLogID, retentionFloorMs)
	if err != nil {
		return nil, err
	}

	const query = `
        SELECT o.log_id, o.event_type, o.agent_id, o.payload_json,
               COALESCE(r.ans_name, ''), COALESCE(r.agent_host, ''),
               COALESCE(r.version, ''), COALESCE(r.display_name, ''),
               COALESCE(r.description, ''),
               COALESCE(e.endpoints, '')
        FROM outbox_events o
        LEFT JOIN agent_registrations r ON r.agent_id = o.agent_id
        LEFT JOIN agent_endpoints e ON e.agent_id = o.agent_id
        WHERE o.sent_at_ms IS NOT NULL
          AND o.log_id IS NOT NULL
          AND o.created_at_ms >= ?
          AND o.id > ?
        ORDER BY o.id ASC
        LIMIT ?`

	rows, err := s.db.db.QueryContext(ctx, query, retentionFloorMs, afterID, limit)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	defer rows.Close()

	out := make([]port.FeedRow, 0, limit)
	for rows.Next() {
		var fr port.FeedRow
		var payload, endpoints string
		if scanErr := rows.Scan(
			&fr.LogID, &fr.EventType, &fr.AgentID, &payload,
			&fr.RegAnsName, &fr.RegAgentHost, &fr.RegVersion,
			&fr.RegDisplayName, &fr.RegDescription, &endpoints,
		); scanErr != nil {
			return nil, fmt.Errorf("sqlite/feed: scan row: %w", scanErr)
		}
		fr.PayloadJSON = []byte(payload)
		if endpoints != "" {
			fr.EndpointsJSON = []byte(endpoints)
		}
		out = append(out, fr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite/feed: iterate rows: %w", err)
	}
	return out, nil
}

// resolveCursor turns the caller's lastLogId into the outbox id to
// page after. An empty cursor pages from the start (id > 0). A cursor
// that does not resolve to a retained row also pages from the start —
// see ReadFeed's doc comment for why expired and never-existed
// collapse to the same behavior.
//
// `ORDER BY id LIMIT 1` makes the resolution deterministic if a logId
// ever maps to more than one outbox row (the TL content-hash-dedupes
// events, so two distinct rows with byte-identical inner events share a
// logId): we page after the LOWEST such id, which is stable across
// calls. See migration 006 for why log_id is not UNIQUE.
func (s *FeedStore) resolveCursor(ctx context.Context, lastLogID string, retentionFloorMs int64) (int64, error) {
	if lastLogID == "" {
		return 0, nil
	}
	var id int64
	const q = `
        SELECT id FROM outbox_events
        WHERE log_id = ?
          AND sent_at_ms IS NOT NULL
          AND created_at_ms >= ?
        ORDER BY id ASC
        LIMIT 1`
	err := s.db.db.QueryRowContext(ctx, q, lastLogID, retentionFloorMs).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Unknown or aged-out cursor: restart from the oldest retained
		// row. Not an error — the contract documents this fallback.
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("sqlite/feed: resolve cursor: %w", err)
	default:
		return id, nil
	}
}

// retentionFloorMs is the epoch-ms lower bound for the retention
// window. When retention is non-positive there is no lower bound
// (return 0 so the >= comparison always passes).
func (s *FeedStore) retentionFloorMs() int64 {
	if s.retention <= 0 {
		return 0
	}
	return s.clock().Add(-s.retention).UnixMilli()
}
