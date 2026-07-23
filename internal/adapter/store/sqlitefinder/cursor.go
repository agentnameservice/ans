package sqlitefinder

import (
	"context"
	"fmt"
	"time"

	"github.com/agentnameservice/ans/internal/finder/index"
)

// Cursor returns the persisted feed position and last-successful-poll
// time. The singleton row is seeded by the initial migration, so this
// never reports "no rows"; a never-polled index returns an empty
// LastLogID and a zero LastPollOK.
func (s *Store) Cursor(ctx context.Context) (index.Cursor, error) {
	var row struct {
		LastLogID    string `db:"last_log_id"`
		LastPollOKMs int64  `db:"last_poll_ok_ms"`
	}
	if err := s.db.GetContext(ctx, &row,
		`SELECT last_log_id, last_poll_ok_ms FROM finder_cursor WHERE id = 1`); err != nil {
		return index.Cursor{}, fmt.Errorf("sqlitefinder: read cursor: %w", err)
	}
	c := index.Cursor{LastLogID: row.LastLogID}
	if row.LastPollOKMs > 0 {
		c.LastPollOK = time.UnixMilli(row.LastPollOKMs).UTC()
	}
	return c, nil
}

// SaveCursor records the feed position and successful-poll time in the
// singleton cursor row. A zero LastPollOK persists as 0 (never-polled);
// the poller always passes a real timestamp after a page applies.
func (s *Store) SaveCursor(ctx context.Context, c index.Cursor) error {
	var pollMs int64
	if !c.LastPollOK.IsZero() {
		pollMs = c.LastPollOK.UnixMilli()
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE finder_cursor SET last_log_id = ?, last_poll_ok_ms = ? WHERE id = 1`,
		c.LastLogID, pollMs); err != nil {
		return fmt.Errorf("sqlitefinder: save cursor: %w", err)
	}
	return nil
}
