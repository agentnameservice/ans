package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// CertificateStore implements port.CertificateStore.
type CertificateStore struct{ db *DB }

// NewCertificateStore returns a new SQLite-backed CertificateStore.
func NewCertificateStore(db *DB) *CertificateStore { return &CertificateStore{db: db} }

// certRow maps an issued_certificates row. serial_number /
// certificate_ref are NULL on rows persisted before migration 007 —
// readers surface them as empty strings and the revocation flow falls
// back to parsing the PEM for the serial.
type certRow struct {
	ID                    int64          `db:"id"`
	AgentID               string         `db:"agent_id"`
	CSRID                 string         `db:"csr_id"`
	CertificateType       string         `db:"certificate_type"`
	CertificatePEM        string         `db:"certificate_pem"`
	ChainPEM              sql.NullString `db:"chain_pem"`
	SerialNumber          sql.NullString `db:"serial_number"`
	CertificateRef        sql.NullString `db:"certificate_ref"`
	Status                string         `db:"status"`
	IssueTimestampMs      int64          `db:"issue_timestamp_ms"`
	ExpirationTimestampMs int64          `db:"expiration_timestamp_ms"`
}

func (r certRow) toDomain() *domain.StoredCertificate {
	return &domain.StoredCertificate{
		InternalID:          r.ID,
		CSRID:               r.CSRID,
		CertificateType:     domain.CertificateType(r.CertificateType),
		CertificatePEM:      r.CertificatePEM,
		ChainPEM:            r.ChainPEM.String,
		SerialNumber:        r.SerialNumber.String,
		CertificateRef:      r.CertificateRef.String,
		Status:              domain.CertificateStatus(r.Status),
		IssueTimestamp:      msToTime(r.IssueTimestampMs),
		ExpirationTimestamp: msToTime(r.ExpirationTimestampMs),
	}
}

// SaveIdentityCertificate persists a newly issued identity certificate.
func (s *CertificateStore) SaveIdentityCertificate(
	ctx context.Context,
	agentID string,
	cert *domain.StoredCertificate,
) error {
	const q = `
        INSERT INTO issued_certificates(
            agent_id, csr_id, certificate_type, certificate_pem, chain_pem,
            serial_number, certificate_ref,
            status, issue_timestamp_ms, expiration_timestamp_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	chain := sql.NullString{}
	if cert.ChainPEM != "" {
		chain = sql.NullString{String: cert.ChainPEM, Valid: true}
	}
	res, err := s.db.extx(ctx).ExecContext(ctx, q,
		agentID, cert.CSRID, string(cert.CertificateType), cert.CertificatePEM, chain,
		nullableString(cert.SerialNumber), nullableString(cert.CertificateRef),
		string(cert.Status), cert.IssueTimestamp.UnixMilli(), cert.ExpirationTimestamp.UnixMilli(),
	)
	if err != nil {
		return mapSQLErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	cert.InternalID = id
	return nil
}

// FindIdentityCertificatesByAgent returns all identity certificates for the agent.
func (s *CertificateStore) FindIdentityCertificatesByAgent(
	ctx context.Context,
	agentID string,
) ([]*domain.StoredCertificate, error) {
	var rows []certRow
	const q = `
        SELECT * FROM issued_certificates
        WHERE agent_id = ? AND certificate_type = 'IDENTITY'
        ORDER BY id DESC`
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, agentID); err != nil {
		return nil, err
	}
	out := make([]*domain.StoredCertificate, len(rows))
	for i, r := range rows {
		out[i] = r.toDomain()
	}
	return out, nil
}

// UpdateCertificateStatus updates only the status field.
func (s *CertificateStore) UpdateCertificateStatus(
	ctx context.Context,
	cert *domain.StoredCertificate,
) error {
	const q = `UPDATE issued_certificates SET status = ? WHERE id = ?`
	_, err := s.db.extx(ctx).ExecContext(ctx, q, string(cert.Status), cert.InternalID)
	return mapSQLErr(err)
}

// SaveCSR persists a new or updated CSR (identity or server).
// Upserts on csr_id; status transitions (PENDING → SIGNED | REJECTED)
// replace the previous row in place.
func (s *CertificateStore) SaveCSR(ctx context.Context, agentID string, csr *domain.AgentCSR) error {
	// Default to IDENTITY when unset for backwards compatibility with
	// older NewIdentityCSR call sites that pre-date the Type field.
	csrType := csr.Type
	if csrType == "" {
		csrType = domain.CSRTypeIdentity
	}
	const q = `
        INSERT INTO agent_csrs(csr_id, agent_id, csr_type, csr_pem, status,
            submission_timestamp_ms, processed_timestamp_ms, rejection_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(csr_id) DO UPDATE SET
            status = excluded.status,
            processed_timestamp_ms = excluded.processed_timestamp_ms,
            rejection_reason = excluded.rejection_reason`
	_, err := s.db.extx(ctx).ExecContext(ctx, q,
		csr.CSRID, agentID, string(csrType), csr.CSRContent, string(csr.Status),
		csr.SubmissionTimestamp.UnixMilli(),
		nullableMs(csr.ProcessedTimestamp),
		nullableString(csr.RejectionReason),
	)
	return mapSQLErr(err)
}

// FindLatestPendingCSRByType returns the newest PENDING CSR of the
// given type (IDENTITY | SERVER) for the agent, or (nil, nil) when
// no such row exists. Used by the verify-acme flow to pick up CSRs
// submitted at register time for signing once domain control is
// proven.
func (s *CertificateStore) FindLatestPendingCSRByType(
	ctx context.Context,
	agentID string,
	csrType domain.CSRType,
) (*domain.AgentCSR, error) {
	var row struct {
		CSRID                 string         `db:"csr_id"`
		AgentID               string         `db:"agent_id"`
		CSRType               sql.NullString `db:"csr_type"`
		CSRPEM                string         `db:"csr_pem"`
		Status                string         `db:"status"`
		SubmissionTimestampMs int64          `db:"submission_timestamp_ms"`
		ProcessedTimestampMs  sql.NullInt64  `db:"processed_timestamp_ms"`
		RejectionReason       sql.NullString `db:"rejection_reason"`
	}
	const q = `
        SELECT * FROM agent_csrs
        WHERE agent_id = ? AND csr_type = ? AND status = ?
        ORDER BY submission_timestamp_ms DESC LIMIT 1`
	err := s.db.extx(ctx).GetContext(ctx, &row, q, agentID, string(csrType), string(domain.CSRStatusPending))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // (nil, nil) signals "no pending CSR"; caller distinguishes via the nil pointer
		}
		return nil, mapSQLErr(err)
	}
	resolvedType := domain.CSRTypeIdentity
	if row.CSRType.Valid && row.CSRType.String != "" {
		resolvedType = domain.CSRType(row.CSRType.String)
	}
	csr := &domain.AgentCSR{
		CSRID:               row.CSRID,
		Type:                resolvedType,
		CSRContent:          row.CSRPEM,
		Status:              domain.CSRStatus(row.Status),
		SubmissionTimestamp: msToTime(row.SubmissionTimestampMs),
	}
	if row.ProcessedTimestampMs.Valid {
		csr.ProcessedTimestamp = msToTime(row.ProcessedTimestampMs.Int64)
	}
	if row.RejectionReason.Valid {
		csr.RejectionReason = row.RejectionReason.String
	}
	return csr, nil
}

// FindCSRByID returns the CSR with the given ID, scoped to the agent.
// Used both by the CSR-status handler (which already knows the agent
// from the URL) and by the registration flow (which refreshes the
// aggregate's embedded slot after a status change).
func (s *CertificateStore) FindCSRByID(
	ctx context.Context,
	agentID, csrID string,
) (*domain.AgentCSR, error) {
	var row struct {
		CSRID                 string         `db:"csr_id"`
		AgentID               string         `db:"agent_id"`
		CSRType               sql.NullString `db:"csr_type"` // NullString for rows from pre-002 schema
		CSRPEM                string         `db:"csr_pem"`
		Status                string         `db:"status"`
		SubmissionTimestampMs int64          `db:"submission_timestamp_ms"`
		ProcessedTimestampMs  sql.NullInt64  `db:"processed_timestamp_ms"`
		RejectionReason       sql.NullString `db:"rejection_reason"`
	}
	const q = `SELECT * FROM agent_csrs WHERE agent_id = ? AND csr_id = ?`
	if err := s.db.extx(ctx).GetContext(ctx, &row, q, agentID, csrID); err != nil {
		return nil, mapSQLErr(err)
	}
	csrType := domain.CSRTypeIdentity
	if row.CSRType.Valid && row.CSRType.String != "" {
		csrType = domain.CSRType(row.CSRType.String)
	}
	csr := &domain.AgentCSR{
		CSRID:               row.CSRID,
		Type:                csrType,
		CSRContent:          row.CSRPEM,
		Status:              domain.CSRStatus(row.Status),
		SubmissionTimestamp: msToTime(row.SubmissionTimestampMs),
	}
	if row.ProcessedTimestampMs.Valid {
		csr.ProcessedTimestamp = msToTime(row.ProcessedTimestampMs.Int64)
	}
	if row.RejectionReason.Valid {
		csr.RejectionReason = row.RejectionReason.String
	}
	return csr, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ = time.Time{} // keep import if future rows need it
