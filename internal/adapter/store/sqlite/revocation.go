package sqlite

import (
	"context"
	"database/sql"

	"github.com/agentnameservice/ans/internal/domain"
)

// RevocationStore implements port.RevocationStore.
type RevocationStore struct{ db *DB }

// NewRevocationStore returns a new SQLite-backed RevocationStore.
func NewRevocationStore(db *DB) *RevocationStore { return &RevocationStore{db: db} }

type revocationRow struct {
	ID             int64          `db:"id"`
	RegistrationID int64          `db:"registration_id"`
	AgentID        string         `db:"agent_id"`
	AnsName        string         `db:"ans_name"`
	PreviousStatus string         `db:"previous_status"`
	Reason         string         `db:"reason"`
	Comments       sql.NullString `db:"comments"`
	RevokedAtMs    int64          `db:"revoked_at_ms"`
}

func (r revocationRow) toDomain() (*domain.AgentRevocation, error) {
	name, err := domain.ParseAnsName(r.AnsName)
	if err != nil {
		return nil, err
	}
	return &domain.AgentRevocation{
		RegistrationID: r.RegistrationID,
		AnsName:        name,
		AgentID:        r.AgentID,
		PreviousStatus: domain.RegistrationStatus(r.PreviousStatus),
		RevokedAt:      msToTime(r.RevokedAtMs),
		Reason:         domain.RevocationReason(r.Reason),
		Comments:       r.Comments.String,
	}, nil
}

// Save persists a revocation record.
func (s *RevocationStore) Save(ctx context.Context, rev *domain.AgentRevocation) error {
	const q = `
        INSERT INTO agent_revocations(
            registration_id, agent_id, ans_name, previous_status,
            reason, comments, revoked_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
	var comments any
	if rev.Comments != "" {
		comments = rev.Comments
	}
	_, err := s.db.extx(ctx).ExecContext(ctx, q,
		rev.RegistrationID, rev.AgentID, rev.AnsName.String(),
		string(rev.PreviousStatus), string(rev.Reason), comments,
		rev.RevokedAt.UnixMilli(),
	)
	return mapSQLErr(err)
}

// FindByAgentID returns the revocation record for an agent.
func (s *RevocationStore) FindByAgentID(ctx context.Context, agentID string) (*domain.AgentRevocation, error) {
	var r revocationRow
	const q = `SELECT * FROM agent_revocations WHERE agent_id = ? ORDER BY id DESC LIMIT 1`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}
