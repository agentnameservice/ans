package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// IdentityStore implements port.IdentityStore.
type IdentityStore struct{ db *DB }

// NewIdentityStore returns a new SQLite-backed IdentityStore.
func NewIdentityStore(db *DB) *IdentityStore { return &IdentityStore{db: db} }

type identityRow struct {
	IdentityID            string         `db:"identity_id"`
	ProviderID            string         `db:"provider_id"`
	Kind                  string         `db:"kind"`
	Value                 string         `db:"value"`
	Status                string         `db:"status"`
	ProofMethod           string         `db:"proof_method"`
	PendingValue          string         `db:"pending_value"`
	ChallengeNonce        sql.NullString `db:"challenge_nonce"`
	ChallengeExpiresAtMs  sql.NullInt64  `db:"challenge_expires_at_ms"`
	ChallengeConsumedAtMs sql.NullInt64  `db:"challenge_consumed_at_ms"`
	VerifiedAtMs          sql.NullInt64  `db:"verified_at_ms"`
	CreatedAtMs           int64          `db:"created_at_ms"`
	UpdatedAtMs           int64          `db:"updated_at_ms"`
}

const identityCols = `identity_id, provider_id, kind, value, status, proof_method,
       pending_value, challenge_nonce, challenge_expires_at_ms,
       challenge_consumed_at_ms, verified_at_ms, created_at_ms, updated_at_ms`

func (r identityRow) toDomain() *domain.VerifiedIdentity {
	v := &domain.VerifiedIdentity{
		IdentityID:   r.IdentityID,
		ProviderID:   r.ProviderID,
		Kind:         domain.IdentifierKind(r.Kind),
		Value:        r.Value,
		Status:       domain.IdentityStatus(r.Status),
		ProofMethod:  r.ProofMethod,
		PendingValue: r.PendingValue,
		CreatedAt:    msToTime(r.CreatedAtMs),
		UpdatedAt:    msToTime(r.UpdatedAtMs),
	}
	if r.VerifiedAtMs.Valid {
		v.VerifiedAt = msToTime(r.VerifiedAtMs.Int64)
	}
	if r.ChallengeNonce.Valid && r.ChallengeNonce.String != "" {
		ch := &domain.IdentityChallenge{Nonce: r.ChallengeNonce.String}
		if r.ChallengeExpiresAtMs.Valid {
			ch.ExpiresAt = msToTime(r.ChallengeExpiresAtMs.Int64)
		}
		if r.ChallengeConsumedAtMs.Valid {
			t := msToTime(r.ChallengeConsumedAtMs.Int64)
			ch.ConsumedAt = &t
		}
		v.Challenge = ch
	}
	return v
}

// Save upserts the aggregate. The partial unique indexes enforce the
// live-row and proven-uniqueness rules; violations surface as
// conflict errors (the service maps them to IDENTIFIER_DUPLICATE).
func (s *IdentityStore) Save(ctx context.Context, v *domain.VerifiedIdentity) error {
	var nonce sql.NullString
	var expiresAt, consumedAt sql.NullInt64
	if v.Challenge != nil {
		nonce = sql.NullString{String: v.Challenge.Nonce, Valid: true}
		if !v.Challenge.ExpiresAt.IsZero() {
			expiresAt = sql.NullInt64{Int64: v.Challenge.ExpiresAt.UnixMilli(), Valid: true}
		}
		if v.Challenge.ConsumedAt != nil {
			consumedAt = sql.NullInt64{Int64: v.Challenge.ConsumedAt.UnixMilli(), Valid: true}
		}
	}
	var verifiedAt sql.NullInt64
	if !v.VerifiedAt.IsZero() {
		verifiedAt = sql.NullInt64{Int64: v.VerifiedAt.UnixMilli(), Valid: true}
	}
	const q = `
        INSERT INTO identities (` + identityCols + `)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(identity_id) DO UPDATE SET
            value                    = excluded.value,
            status                   = excluded.status,
            proof_method             = excluded.proof_method,
            pending_value            = excluded.pending_value,
            challenge_nonce          = excluded.challenge_nonce,
            challenge_expires_at_ms  = excluded.challenge_expires_at_ms,
            challenge_consumed_at_ms = excluded.challenge_consumed_at_ms,
            verified_at_ms           = excluded.verified_at_ms,
            updated_at_ms            = excluded.updated_at_ms`
	_, err := s.db.extx(ctx).ExecContext(ctx, q,
		v.IdentityID, v.ProviderID, string(v.Kind), v.Value, string(v.Status),
		v.ProofMethod, v.PendingValue,
		nonce, expiresAt, consumedAt, verifiedAt,
		v.CreatedAt.UnixMilli(), v.UpdatedAt.UnixMilli(),
	)
	return mapSQLErr(err)
}

// FindByID returns the identity with the given identityId.
func (s *IdentityStore) FindByID(ctx context.Context, identityID string) (*domain.VerifiedIdentity, error) {
	var r identityRow
	err := s.db.extx(ctx).GetContext(ctx, &r,
		`SELECT `+identityCols+` FROM identities WHERE identity_id = ?`, identityID)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain(), nil
}

// FindLive returns the owner's non-REVOKED row for (kind, value).
func (s *IdentityStore) FindLive(
	ctx context.Context,
	providerID string,
	kind domain.IdentifierKind,
	value string,
) (*domain.VerifiedIdentity, error) {
	var r identityRow
	err := s.db.extx(ctx).GetContext(ctx, &r,
		`SELECT `+identityCols+`
         FROM identities
         WHERE provider_id = ? AND kind = ? AND value = ? AND status != 'REVOKED'`,
		providerID, string(kind), value)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain(), nil
}

// ExistsVerified reports whether any owner holds a VERIFIED row for
// (kind, value).
func (s *IdentityStore) ExistsVerified(ctx context.Context, kind domain.IdentifierKind, value string) (bool, error) {
	var one int
	err := s.db.extx(ctx).GetContext(ctx, &one, `
        SELECT 1 FROM identities
        WHERE kind = ? AND value = ? AND status = 'VERIFIED'`,
		string(kind), value)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, err
	}
}

// ListByOwner returns every identity owned by the principal, newest
// first.
func (s *IdentityStore) ListByOwner(ctx context.Context, providerID string) ([]*domain.VerifiedIdentity, error) {
	var rows []identityRow
	err := s.db.extx(ctx).SelectContext(ctx, &rows,
		`SELECT `+identityCols+`
         FROM identities
         WHERE provider_id = ?
         ORDER BY created_at_ms DESC, identity_id DESC`, providerID)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	out := make([]*domain.VerifiedIdentity, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toDomain())
	}
	return out, nil
}

// ConsumeChallenge atomically consumes the live challenge nonce. The
// conditional UPDATE is the TOCTOU guard: only one of two concurrent
// verify-control calls can flip challenge_consumed_at_ms from NULL,
// and an expired or superseded nonce matches zero rows.
func (s *IdentityStore) ConsumeChallenge(ctx context.Context, identityID, nonce string, now time.Time) error {
	res, err := s.db.extx(ctx).ExecContext(ctx, `
        UPDATE identities
        SET challenge_consumed_at_ms = ?, updated_at_ms = ?
        WHERE identity_id = ?
          AND challenge_nonce = ?
          AND challenge_consumed_at_ms IS NULL
          AND challenge_expires_at_ms > ?`,
		now.UnixMilli(), now.UnixMilli(), identityID, nonce, now.UnixMilli())
	if err != nil {
		return mapSQLErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.NewInvalidStateError("PRICC_TOKEN_ALREADY_USED",
			"challenge nonce is consumed, expired, or superseded")
	}
	return nil
}

// IdentityLinkStore implements port.IdentityLinkStore.
type IdentityLinkStore struct{ db *DB }

// NewIdentityLinkStore returns a new SQLite-backed IdentityLinkStore.
func NewIdentityLinkStore(db *DB) *IdentityLinkStore { return &IdentityLinkStore{db: db} }

type identityLinkRow struct {
	IdentityID  string        `db:"identity_id"`
	AgentID     string        `db:"agent_id"`
	Status      string        `db:"status"`
	LinkedAtMs  sql.NullInt64 `db:"linked_at_ms"`
	CreatedAtMs int64         `db:"created_at_ms"`
	UpdatedAtMs int64         `db:"updated_at_ms"`
}

func (r identityLinkRow) toDomain() *domain.IdentityLink {
	l := &domain.IdentityLink{
		IdentityID: r.IdentityID,
		AgentID:    r.AgentID,
		Status:     domain.LinkStatus(r.Status),
		CreatedAt:  msToTime(r.CreatedAtMs),
		UpdatedAt:  msToTime(r.UpdatedAtMs),
	}
	if r.LinkedAtMs.Valid {
		l.LinkedAt = msToTime(r.LinkedAtMs.Int64)
	}
	return l
}

// Link upserts a live link for the pair. Idempotent: returns false
// (and no error) when the pair is already LINKED, so batch calls can
// skip already-linked agents in the sealed event.
func (s *IdentityLinkStore) Link(ctx context.Context, identityID, agentID string, now time.Time) (bool, error) {
	// Fast path: already live?
	var exists int
	err := s.db.extx(ctx).GetContext(ctx, &exists, `
        SELECT 1 FROM identity_links
        WHERE identity_id = ? AND agent_id = ? AND status = 'LINKED'`,
		identityID, agentID)
	switch {
	case err == nil:
		return false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	nowMs := now.UnixMilli()
	_, err = s.db.extx(ctx).ExecContext(ctx, `
        INSERT INTO identity_links (identity_id, agent_id, status, linked_at_ms, created_at_ms, updated_at_ms)
        VALUES (?, ?, 'LINKED', ?, ?, ?)`,
		identityID, agentID, nowMs, nowMs, nowMs)
	if err != nil {
		return false, mapSQLErr(err)
	}
	return true, nil
}

// Unlink flips the live link to UNLINKED.
func (s *IdentityLinkStore) Unlink(ctx context.Context, identityID, agentID string, now time.Time) error {
	res, err := s.db.extx(ctx).ExecContext(ctx, `
        UPDATE identity_links
        SET status = 'UNLINKED', updated_at_ms = ?
        WHERE identity_id = ? AND agent_id = ? AND status = 'LINKED'`,
		now.UnixMilli(), identityID, agentID)
	if err != nil {
		return mapSQLErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.NewNotFoundError("LINK_NOT_FOUND",
			"no live link exists for this identity and agent")
	}
	return nil
}

// ListLiveByIdentity returns the identity's live links.
func (s *IdentityLinkStore) ListLiveByIdentity(ctx context.Context, identityID string) ([]*domain.IdentityLink, error) {
	return s.listLive(ctx, `identity_id = ?`, identityID)
}

// ListLiveByAgent returns the agent's live links.
func (s *IdentityLinkStore) ListLiveByAgent(ctx context.Context, agentID string) ([]*domain.IdentityLink, error) {
	return s.listLive(ctx, `agent_id = ?`, agentID)
}

func (s *IdentityLinkStore) listLive(ctx context.Context, where string, arg string) ([]*domain.IdentityLink, error) {
	var rows []identityLinkRow
	err := s.db.extx(ctx).SelectContext(ctx, &rows, `
        SELECT identity_id, agent_id, status, linked_at_ms, created_at_ms, updated_at_ms
        FROM identity_links
        WHERE `+where+` AND status = 'LINKED'
        ORDER BY linked_at_ms DESC, id DESC`, arg)
	if err != nil {
		return nil, mapSQLErr(err)
	}
	out := make([]*domain.IdentityLink, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toDomain())
	}
	return out, nil
}
