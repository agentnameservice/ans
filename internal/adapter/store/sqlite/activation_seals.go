package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// LoadActivationSeal retrieves the original lane and signed payload, if prepared.
func (s *OutboxStore) LoadActivationSeal(ctx context.Context, agentID string) (string, []byte, error) {
	var row struct {
		Lane    string `db:"schema_version"`
		Payload string `db:"payload_json"`
	}
	err := s.db.extx(ctx).GetContext(ctx, &row,
		`SELECT schema_version, payload_json FROM activation_seals WHERE agent_id = ?`, agentID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, mapSQLErr(err)
	}
	return row.Lane, []byte(row.Payload), nil
}

// PrepareActivationSeal atomically elects one payload for concurrent attempts.
// The insert commits before sealing; on conflict every caller reads the winner.
func (s *OutboxStore) PrepareActivationSeal(ctx context.Context, agentID, lane string, payload []byte) (string, []byte, error) {
	_, err := s.db.extx(ctx).ExecContext(ctx,
		`INSERT INTO activation_seals (agent_id, schema_version, payload_json, created_at_ms)
         VALUES (?, ?, ?, ?) ON CONFLICT(agent_id) DO NOTHING`, agentID, lane, string(payload), time.Now().UnixMilli())
	if err != nil {
		return "", nil, mapSQLErr(err)
	}
	return s.LoadActivationSeal(ctx, agentID)
}
