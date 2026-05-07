package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// EndpointStore implements port.EndpointStore.
type EndpointStore struct{ db *DB }

// NewEndpointStore returns a new SQLite-backed EndpointStore.
func NewEndpointStore(db *DB) *EndpointStore { return &EndpointStore{db: db} }

// Save upserts the endpoint collection for the given agent.
func (s *EndpointStore) Save(ctx context.Context, endpoints *domain.AgentEndpoints) error {
	if endpoints == nil {
		return errors.New("sqlite: endpoints is nil")
	}
	jsonBytes, err := json.Marshal(endpoints.Endpoints)
	if err != nil {
		return fmt.Errorf("sqlite: marshal endpoints: %w", err)
	}
	const q = `
        INSERT INTO agent_endpoints(agent_id, endpoints, updated_at_ms)
        VALUES(?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            endpoints = excluded.endpoints,
            updated_at_ms = excluded.updated_at_ms`
	_, err = s.db.extx(ctx).ExecContext(ctx, q, endpoints.AgentID, string(jsonBytes), time.Now().UnixMilli())
	return mapSQLErr(err)
}

// FindByAgentID returns the endpoint collection for the given agent.
func (s *EndpointStore) FindByAgentID(ctx context.Context, agentID string) (*domain.AgentEndpoints, error) {
	var row struct {
		AgentID   string `db:"agent_id"`
		Endpoints string `db:"endpoints"`
	}
	const q = `SELECT agent_id, endpoints FROM agent_endpoints WHERE agent_id = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &row, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	var eps []domain.AgentEndpoint
	if err := json.Unmarshal([]byte(row.Endpoints), &eps); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal endpoints: %w", err)
	}
	return &domain.AgentEndpoints{AgentID: row.AgentID, Endpoints: eps}, nil
}

// FindByAgentIDs returns endpoints for multiple agents in a single query.
func (s *EndpointStore) FindByAgentIDs(
	ctx context.Context,
	agentIDs []string,
) (map[string]*domain.AgentEndpoints, error) {
	if len(agentIDs) == 0 {
		return map[string]*domain.AgentEndpoints{}, nil
	}
	placeholders := make([]string, len(agentIDs))
	args := make([]any, len(agentIDs))
	for i, id := range agentIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	q := fmt.Sprintf(
		`SELECT agent_id, endpoints FROM agent_endpoints WHERE agent_id IN (%s)`,
		joinStrings(placeholders, ","),
	)
	var rows []struct {
		AgentID   string `db:"agent_id"`
		Endpoints string `db:"endpoints"`
	}
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, mapSQLErr(err)
	}
	out := make(map[string]*domain.AgentEndpoints, len(rows))
	for _, r := range rows {
		var eps []domain.AgentEndpoint
		if err := json.Unmarshal([]byte(r.Endpoints), &eps); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal endpoints: %w", err)
		}
		out[r.AgentID] = &domain.AgentEndpoints{AgentID: r.AgentID, Endpoints: eps}
	}
	return out, nil
}
