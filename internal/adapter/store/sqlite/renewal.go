package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

// RenewalStore implements port.RenewalStore.
type RenewalStore struct{ db *DB }

// NewRenewalStore returns a new SQLite-backed RenewalStore.
func NewRenewalStore(db *DB) *RenewalStore { return &RenewalStore{db: db} }

// renewalRow maps a single server_cert_renewals row for scanning.
//
// The `dns01_token` / `http01_token` columns are legacy: rows written
// before migration 008 carried bare RA-generated tokens instead of a
// challenge set from the certificate order. Readers synthesize
// self-issued challenges from them when the `challenges` JSON column
// is NULL. New rows still fill the token columns (they are NOT NULL
// in the original schema) but readers prefer the JSON.
type renewalRow struct {
	ID                  int64          `db:"id"`
	AgentID             string         `db:"agent_id"`
	RegistrationID      int64          `db:"registration_id"`
	RenewalType         string         `db:"renewal_type"`
	ServerCsrID         sql.NullString `db:"server_csr_id"`
	ByocCertPEM         sql.NullString `db:"byoc_cert_pem"`
	ByocChainPEM        sql.NullString `db:"byoc_chain_pem"`
	DNS01Token          string         `db:"dns01_token"`
	HTTP01Token         string         `db:"http01_token"`
	OrderRef            sql.NullString `db:"order_ref"`
	Challenges          sql.NullString `db:"challenges"`
	ValidationStatus    string         `db:"validation_status"`
	ValidationExpiresMs int64          `db:"validation_expires_ms"`
	FailureReason       sql.NullString `db:"failure_reason"`
	CompletedAtMs       sql.NullInt64  `db:"completed_at_ms"`
	CreatedAtMs         int64          `db:"created_at_ms"`
	UpdatedAtMs         int64          `db:"updated_at_ms"`
}

func (r renewalRow) toDomain() (*domain.ServerCertificateRenewal, error) {
	v := domain.RenewalValidation{
		OrderRef:  r.OrderRef.String,
		Status:    domain.ValidationStatus(r.ValidationStatus),
		CreatedAt: msToTime(r.CreatedAtMs),
		ExpiresAt: msToTime(r.ValidationExpiresMs),
		UpdatedAt: msToTime(r.UpdatedAtMs),
	}
	switch {
	case r.Challenges.Valid && r.Challenges.String != "":
		if err := json.Unmarshal([]byte(r.Challenges.String), &v.Challenges); err != nil {
			return nil, fmt.Errorf("sqlite: decode renewal challenges: %w", err)
		}
	default:
		// Legacy row: synthesize the self-issued pair from the bare
		// token columns.
		v.Challenges = []domain.Challenge{
			{Type: domain.ChallengeTypeDNS01, Token: r.DNS01Token},
			{Type: domain.ChallengeTypeHTTP01, Token: r.HTTP01Token},
		}
	}
	ren := &domain.ServerCertificateRenewal{
		ID:             r.ID,
		AgentID:        r.AgentID,
		RegistrationID: r.RegistrationID,
		RenewalType:    domain.RenewalType(r.RenewalType),
		ServerCsrID:    r.ServerCsrID.String,
		ByocCertPEM:    r.ByocCertPEM.String,
		ByocChainPEM:   r.ByocChainPEM.String,
		FailureReason:  r.FailureReason.String,
		CreatedAt:      msToTime(r.CreatedAtMs),
		Validation:     v,
	}
	if r.CompletedAtMs.Valid {
		ren.CompletedAt = msToTime(r.CompletedAtMs.Int64)
	}
	return ren, nil
}

// Save inserts or updates a renewal aggregate.
func (s *RenewalStore) Save(ctx context.Context, r *domain.ServerCertificateRenewal) error {
	now := time.Now().UnixMilli()
	if r.ID == 0 {
		challengesJSON, err := json.Marshal(r.Validation.Challenges)
		if err != nil {
			return fmt.Errorf("sqlite: encode renewal challenges: %w", err)
		}
		// The bare token columns are NOT NULL in the original schema;
		// fill them from the challenge set so pre-006 tooling reading
		// the table sees sane values.
		dns01, _ := r.Validation.ChallengeOfType(domain.ChallengeTypeDNS01)
		http01, _ := r.Validation.ChallengeOfType(domain.ChallengeTypeHTTP01)
		const q = `
            INSERT INTO server_cert_renewals(
                agent_id, registration_id, renewal_type, server_csr_id,
                byoc_cert_pem, byoc_chain_pem,
                dns01_token, http01_token, order_ref, challenges,
                validation_status, validation_expires_ms,
                failure_reason, completed_at_ms, created_at_ms, updated_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := s.db.extx(ctx).ExecContext(ctx, q,
			r.AgentID, r.RegistrationID, string(r.RenewalType),
			nullableString(r.ServerCsrID),
			nullableString(r.ByocCertPEM), nullableString(r.ByocChainPEM),
			dns01.Token, http01.Token,
			nullableString(r.Validation.OrderRef), string(challengesJSON),
			string(r.Validation.Status), r.Validation.ExpiresAt.UnixMilli(),
			nullableString(r.FailureReason),
			nullableMs(r.CompletedAt),
			r.CreatedAt.UnixMilli(), now,
		)
		if err != nil {
			return mapSQLErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		r.ID = id
		return nil
	}
	const q = `
        UPDATE server_cert_renewals SET
            validation_status = ?,
            failure_reason = ?,
            completed_at_ms = ?,
            updated_at_ms = ?
        WHERE id = ?`
	_, err := s.db.extx(ctx).ExecContext(ctx, q,
		string(r.Validation.Status),
		nullableString(r.FailureReason),
		nullableMs(r.CompletedAt),
		now,
		r.ID,
	)
	return mapSQLErr(err)
}

// FindByAgentID returns the most recent renewal for the agent.
func (s *RenewalStore) FindByAgentID(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error) {
	var r renewalRow
	const q = `SELECT * FROM server_cert_renewals WHERE agent_id = ? ORDER BY id DESC LIMIT 1`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}

// FindPendingByAgentID returns a pending (not-completed) renewal.
func (s *RenewalStore) FindPendingByAgentID(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error) {
	var r renewalRow
	const q = `
        SELECT * FROM server_cert_renewals
        WHERE agent_id = ? AND completed_at_ms IS NULL
        ORDER BY id DESC LIMIT 1`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}

// Delete removes a renewal by ID.
func (s *RenewalStore) Delete(ctx context.Context, id int64) error {
	_, err := s.db.extx(ctx).ExecContext(ctx, `DELETE FROM server_cert_renewals WHERE id = ?`, id)
	return mapSQLErr(err)
}

// ListPendingExpired returns renewals whose validation window has elapsed
// without verification.
func (s *RenewalStore) ListPendingExpired(ctx context.Context) ([]*domain.ServerCertificateRenewal, error) {
	nowMs := time.Now().UnixMilli()
	var rows []renewalRow
	const q = `
        SELECT * FROM server_cert_renewals
        WHERE completed_at_ms IS NULL
          AND validation_status = 'PENDING'
          AND validation_expires_ms <= ?`
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, nowMs); err != nil {
		return nil, mapSQLErr(err)
	}
	out := make([]*domain.ServerCertificateRenewal, len(rows))
	for i, r := range rows {
		ren, err := r.toDomain()
		if err != nil {
			return nil, err
		}
		out[i] = ren
	}
	return out, nil
}
