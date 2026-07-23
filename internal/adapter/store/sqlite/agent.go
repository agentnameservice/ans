package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// AgentStore implements port.AgentStore.
type AgentStore struct {
	db *DB
}

// NewAgentStore returns a new SQLite-backed AgentStore.
func NewAgentStore(db *DB) *AgentStore { return &AgentStore{db: db} }

// agentRow maps a single agent_registrations row for scanning.
//
// The `acme_dns01_token` column is legacy: rows written before
// migration 008 carried a single RA-generated DNS-01 token instead of
// a certificate order. Readers synthesize a self-issued order from it
// when the order columns are NULL; writers only fill the order
// columns. `acme_challenge_expires_at_ms` is shared between both
// generations — its semantic (challenge-window expiry) is unchanged,
// so it stores the order expiry.
type agentRow struct {
	ID                       int64          `db:"id"`
	AgentID                  string         `db:"agent_id"`
	OwnerID                  string         `db:"owner_id"`
	AnsName                  string         `db:"ans_name"`
	AgentHost                string         `db:"agent_host"`
	Version                  string         `db:"version"`
	Status                   string         `db:"status"`
	DisplayName              string         `db:"display_name"`
	Description              string         `db:"description"`
	RegistrationTimestampMs  int64          `db:"registration_timestamp_ms"`
	LastRenewalTimestampMs   sql.NullInt64  `db:"last_renewal_timestamp_ms"`
	SupersedesRegistrationID sql.NullInt64  `db:"supersedes_registration_id"`
	ACMEDNS01Token           sql.NullString `db:"acme_dns01_token"`
	ACMEChallengeExpiresAtMs sql.NullInt64  `db:"acme_challenge_expires_at_ms"`
	DiscoveryProfiles        sql.NullString `db:"discovery_profiles"`
	CertOrderRef             sql.NullString `db:"cert_order_ref"`
	CertOrderState           sql.NullString `db:"cert_order_state"`
	CertOrderChallenges      sql.NullString `db:"cert_order_challenges"`
	CertOrderVerified        sql.NullString `db:"cert_order_verified_challenge"`
	CreatedAtMs              int64          `db:"created_at_ms"`
	UpdatedAtMs              int64          `db:"updated_at_ms"`
}

func (r agentRow) toDomain() (*domain.AgentRegistration, error) {
	ansName, err := domain.ParseAnsName(r.AnsName)
	if err != nil {
		return nil, fmt.Errorf("sqlite: decode ans_name: %w", err)
	}

	reg := &domain.AgentRegistration{
		ID:      r.ID,
		AgentID: r.AgentID,
		OwnerID: r.OwnerID,
		AnsName: ansName,
		Status:  domain.RegistrationStatus(r.Status),
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: msToTime(r.RegistrationTimestampMs),
			DisplayName:           r.DisplayName,
			Description:           r.Description,
		},
	}
	if r.LastRenewalTimestampMs.Valid {
		reg.Details.LastRenewalTimestamp = msToTime(r.LastRenewalTimestampMs.Int64)
	}
	if r.SupersedesRegistrationID.Valid {
		reg.SupersedesRegistrationID = r.SupersedesRegistrationID.Int64
	}
	order, err := certOrderFromRow(
		r.CertOrderRef, r.CertOrderState, r.CertOrderChallenges,
		r.CertOrderVerified, r.ACMEDNS01Token, r.ACMEChallengeExpiresAtMs,
	)
	if err != nil {
		return nil, err
	}
	reg.CertOrder = order
	if r.DiscoveryProfiles.Valid && r.DiscoveryProfiles.String != "" {
		profiles, err := decodeDiscoveryProfiles(r.DiscoveryProfiles.String)
		if err != nil {
			return nil, fmt.Errorf("sqlite: decode discovery_profiles: %w", err)
		}
		reg.DiscoveryProfiles = profiles
	}
	return reg, nil
}

// decodeDiscoveryProfiles parses the JSON-array string stored in
// agent_registrations.discovery_profiles into the typed domain slice.
// Empty array unmarshals to a nil slice (the domain layer treats
// empty as "use default") so post-load behavior matches a freshly
// registered agent that didn't set the field.
func decodeDiscoveryProfiles(raw string) ([]domain.DiscoveryProfile, error) {
	var strs []string
	if err := json.Unmarshal([]byte(raw), &strs); err != nil {
		return nil, err
	}
	if len(strs) == 0 {
		return nil, nil
	}
	out := make([]domain.DiscoveryProfile, len(strs))
	for i, s := range strs {
		out[i] = domain.DiscoveryProfile(s)
	}
	return out, nil
}

// encodeDiscoveryProfiles renders a typed profile slice as the canonical
// JSON-array string the agent_registrations.discovery_profiles column
// stores. nil/empty input renders empty string so nullableString()
// stamps SQL NULL — domain treats NULL the same as the default set
// per ComputeRequiredDNSRecords.
func encodeDiscoveryProfiles(profiles []domain.DiscoveryProfile) string {
	if len(profiles) == 0 {
		return ""
	}
	strs := make([]string, len(profiles))
	for i, s := range profiles {
		strs[i] = string(s)
	}
	b, err := json.Marshal(strs)
	if err != nil {
		// Marshalling a []string never errors in practice; surface as
		// empty so the column is NULL rather than corrupted JSON.
		return ""
	}
	return string(b)
}

// certOrderFromRow decodes the certificate order from its columns,
// falling back to synthesizing a self-issued single-DNS-01 order from
// the legacy token columns for rows written before migration 008.
func certOrderFromRow(
	ref, state, challengesJSON, verifiedChallenge sql.NullString,
	legacyDNS01 sql.NullString, legacyExpiresMs sql.NullInt64,
) (domain.CertificateOrder, error) {
	var order domain.CertificateOrder
	if challengesJSON.Valid && challengesJSON.String != "" {
		if err := json.Unmarshal([]byte(challengesJSON.String), &order.Challenges); err != nil {
			return domain.CertificateOrder{}, fmt.Errorf("sqlite: decode cert_order_challenges: %w", err)
		}
		order.OrderRef = ref.String
		order.State = domain.OrderState(state.String)
		// NULL (rows written before migration 012, or a gate that has
		// not passed yet) decodes to the empty type — "not recorded".
		order.VerifiedChallenge = domain.ChallengeType(verifiedChallenge.String)
		if legacyExpiresMs.Valid {
			order.ExpiresAt = msToTime(legacyExpiresMs.Int64)
		}
		return order, nil
	}
	// Legacy row: single RA-generated DNS-01 token, implicitly PENDING
	// while the agent still sits in a pre-validation state.
	if legacyDNS01.Valid && legacyDNS01.String != "" {
		order.State = domain.OrderStatePending
		order.Challenges = []domain.Challenge{{
			Type:  domain.ChallengeTypeDNS01,
			Token: legacyDNS01.String,
		}}
		if legacyExpiresMs.Valid {
			order.ExpiresAt = msToTime(legacyExpiresMs.Int64)
		}
	}
	return order, nil
}

// certOrderColumns is the SQL-bindable representation of a
// CertificateOrder. Zero orders bind as NULLs so legacy-row synthesis
// stays distinguishable from an empty order.
type certOrderColumns struct {
	ref        any
	state      any
	challenges any
	verified   any
	expiresMs  any
}

// certOrderToRow encodes the order for persistence. The challenge
// array is stored verbatim as JSON.
func certOrderToRow(order domain.CertificateOrder) (certOrderColumns, error) {
	if order.IsZero() {
		return certOrderColumns{}, nil
	}
	encoded, err := json.Marshal(order.Challenges)
	if err != nil {
		return certOrderColumns{}, fmt.Errorf("sqlite: encode cert_order_challenges: %w", err)
	}
	return certOrderColumns{
		ref:        nullableString(order.OrderRef),
		state:      string(order.State),
		challenges: string(encoded),
		verified:   nullableString(string(order.VerifiedChallenge)),
		expiresMs:  nullableMs(order.ExpiresAt),
	}, nil
}

// Save inserts or updates an AgentRegistration. Endpoints, server cert,
// and identity CSR are persisted via their dedicated tables — Save only
// writes the root aggregate row.
func (s *AgentStore) Save(ctx context.Context, agent *domain.AgentRegistration) error {
	if agent == nil {
		return errors.New("sqlite: agent is nil")
	}
	now := time.Now().UnixMilli()

	order, err := certOrderToRow(agent.CertOrder)
	if err != nil {
		return err
	}

	if agent.ID == 0 {
		const q = `
            INSERT INTO agent_registrations (
                agent_id, owner_id, ans_name, agent_host, version, status,
                display_name, description,
                registration_timestamp_ms, last_renewal_timestamp_ms,
                supersedes_registration_id,
                cert_order_ref, cert_order_state, cert_order_challenges,
                cert_order_verified_challenge,
                acme_challenge_expires_at_ms,
                discovery_profiles,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := s.db.extx(ctx).ExecContext(ctx, q,
			agent.AgentID,
			agent.OwnerID,
			agent.AnsName.String(),
			agent.AnsName.FQDN(),
			agent.AnsName.Version().String(),
			string(agent.Status),
			agent.Details.DisplayName,
			agent.Details.Description,
			agent.Details.RegistrationTimestamp.UnixMilli(),
			nullableMs(agent.Details.LastRenewalTimestamp),
			nullableInt64(agent.SupersedesRegistrationID),
			order.ref, order.state, order.challenges,
			order.verified,
			order.expiresMs,
			nullableString(encodeDiscoveryProfiles(agent.DiscoveryProfiles)),
			now, now,
		)
		if err != nil {
			return mapSQLErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("sqlite: last insert id: %w", err)
		}
		agent.ID = id
		return nil
	}

	const q = `
        UPDATE agent_registrations SET
            status = ?,
            display_name = ?,
            description = ?,
            last_renewal_timestamp_ms = ?,
            supersedes_registration_id = ?,
            cert_order_ref = ?,
            cert_order_state = ?,
            cert_order_challenges = ?,
            cert_order_verified_challenge = ?,
            acme_challenge_expires_at_ms = ?,
            discovery_profiles = ?,
            updated_at_ms = ?
        WHERE id = ?`
	_, err = s.db.extx(ctx).ExecContext(ctx, q,
		string(agent.Status),
		agent.Details.DisplayName,
		agent.Details.Description,
		nullableMs(agent.Details.LastRenewalTimestamp),
		nullableInt64(agent.SupersedesRegistrationID),
		order.ref, order.state, order.challenges,
		order.verified,
		order.expiresMs,
		nullableString(encodeDiscoveryProfiles(agent.DiscoveryProfiles)),
		now,
		agent.ID,
	)
	return mapSQLErr(err)
}

// FindByID looks up a registration by primary key.
func (s *AgentStore) FindByID(ctx context.Context, id int64) (*domain.AgentRegistration, error) {
	var r agentRow
	const q = `SELECT * FROM agent_registrations WHERE id = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, id); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}

// FindByAgentID looks up a registration by agent UUID.
func (s *AgentStore) FindByAgentID(ctx context.Context, agentID string) (*domain.AgentRegistration, error) {
	var r agentRow
	const q = `SELECT * FROM agent_registrations WHERE agent_id = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}

// FindByAnsName looks up a registration by versioned ANS name.
func (s *AgentStore) FindByAnsName(ctx context.Context, ansName domain.AnsName) (*domain.AgentRegistration, error) {
	var r agentRow
	const q = `SELECT * FROM agent_registrations WHERE ans_name = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, ansName.String()); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}

// ExistsByAnsName returns true if any row uses the given ANS name.
func (s *AgentStore) ExistsByAnsName(ctx context.Context, ansName domain.AnsName) (bool, error) {
	var n int
	const q = `SELECT COUNT(1) FROM agent_registrations WHERE ans_name = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &n, q, ansName.String()); err != nil {
		return false, err
	}
	return n > 0, nil
}

// FindAllByAgentHost returns all registrations for a given FQDN, newest first.
func (s *AgentStore) FindAllByAgentHost(ctx context.Context, host string) ([]*domain.AgentRegistration, error) {
	var rows []agentRow
	const q = `SELECT * FROM agent_registrations WHERE agent_host = ? ORDER BY id DESC`
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, host); err != nil {
		return nil, err
	}
	return rowsToDomain(rows)
}

// FindExistingByFQDN returns ACTIVE or PENDING_* registrations for the FQDN.
func (s *AgentStore) FindExistingByFQDN(ctx context.Context, fqdn string) ([]*domain.AgentRegistration, error) {
	var rows []agentRow
	const q = `
        SELECT * FROM agent_registrations
        WHERE agent_host = ?
          AND status IN ('ACTIVE', 'PENDING_VALIDATION', 'PENDING_CERTS', 'PENDING_DNS')
        ORDER BY id DESC`
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, fqdn); err != nil {
		return nil, err
	}
	return rowsToDomain(rows)
}

// ListByOwner returns a cursor-paginated list of owned agents.
func (s *AgentStore) ListByOwner(
	ctx context.Context,
	ownerID string,
	filter port.ListFilter,
) (*port.CursorPage[*domain.AgentRegistration], error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	args := []any{ownerID}
	where := "owner_id = ?"

	if filter.AgentHost != "" {
		where += " AND agent_host = ?"
		args = append(args, filter.AgentHost)
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			placeholders[i] = "?"
			args = append(args, string(s))
		}
		where += fmt.Sprintf(" AND status IN (%s)", joinStrings(placeholders, ","))
	}

	// Cursor = id of last row seen, encoded base64 for opacity.
	if filter.Cursor != "" {
		id, err := decodeCursor(filter.Cursor)
		if err != nil {
			return nil, domain.NewValidationError("INVALID_CURSOR", err.Error())
		}
		where += " AND id < ?"
		args = append(args, id)
	}

	q := fmt.Sprintf(
		`SELECT * FROM agent_registrations WHERE %s ORDER BY id DESC LIMIT ?`,
		where,
	)
	args = append(args, limit+1)

	var rows []agentRow
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, err
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	items, err := rowsToDomain(rows)
	if err != nil {
		return nil, err
	}
	nextCursor := ""
	if hasMore && len(items) > 0 {
		nextCursor = encodeCursor(items[len(items)-1].ID)
	}
	return &port.CursorPage[*domain.AgentRegistration]{
		Items:         items,
		NextCursor:    nextCursor,
		HasMore:       hasMore,
		ReturnedCount: len(items),
	}, nil
}

// ExpireLapsedPendingValidation flips lapsed PENDING_VALIDATION rows
// to EXPIRED in one guarded UPDATE and returns the count.
//
// The WHERE clause is the concurrency guard: a row is expired only
// while it is still PENDING_VALIDATION, its challenge window
// (acme_challenge_expires_at_ms — shared between the legacy
// single-token era and the order era) has lapsed, AND its order is
// still PENDING. A concurrent verify-acme that advances the row
// (status → PENDING_DNS, or order → ISSUING/COMPLETED/FAILED) removes
// it from the match set, so the sweep can never clobber a
// successfully-validated registration or roll its order columns back.
// Rows with a NULL expiry (pre-challenge-persistence registrations)
// never match — they carry no window to expire on and remain
// cancellable instead. Legacy rows have a NULL cert_order_state and
// are matched by the IS NULL arm.
func (s *AgentStore) ExpireLapsedPendingValidation(ctx context.Context, now time.Time) (int64, error) {
	const q = `
        UPDATE agent_registrations
        SET status = 'EXPIRED', updated_at_ms = ?
        WHERE status = 'PENDING_VALIDATION'
          AND acme_challenge_expires_at_ms IS NOT NULL
          AND acme_challenge_expires_at_ms <= ?
          AND (cert_order_state IS NULL OR cert_order_state = 'PENDING')`
	nowMs := now.UnixMilli()
	res, err := s.db.extx(ctx).ExecContext(ctx, q, nowMs, nowMs)
	if err != nil {
		return 0, mapSQLErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: expire lapsed registrations: rows affected: %w", err)
	}
	return n, nil
}

// Delete removes a registration by ID.
func (s *AgentStore) Delete(ctx context.Context, id int64) error {
	_, err := s.db.extx(ctx).ExecContext(ctx, `DELETE FROM agent_registrations WHERE id = ?`, id)
	return mapSQLErr(err)
}

// helpers

func rowsToDomain(rows []agentRow) ([]*domain.AgentRegistration, error) {
	out := make([]*domain.AgentRegistration, len(rows))
	for i, r := range rows {
		d, err := r.toDomain()
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}

func msToTime(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

func nullableMs(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMilli()
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func joinStrings(s []string, sep string) string {
	out := ""
	var outSb324 strings.Builder
	for i, v := range s {
		if i > 0 {
			outSb324.WriteString(sep)
		}
		outSb324.WriteString(v)
	}
	out += outSb324.String()
	return out
}

// encodeCursor / decodeCursor keep cursors opaque to clients. A future
// adapter may switch to a Cuid2 or timestamp-based cursor without
// breaking API compatibility.
func encodeCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeCursor(c string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, fmt.Errorf("malformed cursor: %w", err)
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed cursor: %w", err)
	}
	return id, nil
}
