package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ByocCertificateStore implements port.ByocCertificateStore.
type ByocCertificateStore struct{ db *DB }

// NewByocCertificateStore returns a new SQLite-backed store.
func NewByocCertificateStore(db *DB) *ByocCertificateStore { return &ByocCertificateStore{db: db} }

// byocRow maps a byoc_certificates row.
type byocRow struct {
	ID          int64          `db:"id"`
	AgentID     string         `db:"agent_id"`
	LeafPEM     string         `db:"leaf_pem"`
	ChainPEM    sql.NullString `db:"chain_pem"`
	CN          string         `db:"cn"`
	SANs        string         `db:"sans"`
	IssuerDN    string         `db:"issuer_dn"`
	ValidFromMs int64          `db:"valid_from_ms"`
	ValidToMs   int64          `db:"valid_to_ms"`
	Fingerprint string         `db:"fingerprint"`
	CreatedAtMs int64          `db:"created_at_ms"`
}

func (r byocRow) toDomain() (*domain.ByocServerCertificate, error) {
	var sans []string
	if err := json.Unmarshal([]byte(r.SANs), &sans); err != nil {
		return nil, err
	}
	return &domain.ByocServerCertificate{
		LeafCertificatePEM:      r.LeafPEM,
		ChainCertificatesPEM:    r.ChainPEM.String,
		SubjectCommonName:       r.CN,
		SubjectAlternativeNames: sans,
		IssuerDN:                r.IssuerDN,
		ValidFromTimestamp:      msToTime(r.ValidFromMs),
		ValidToTimestamp:        msToTime(r.ValidToMs),
		Fingerprint:             r.Fingerprint,
	}, nil
}

// Save persists a BYOC server certificate.
func (s *ByocCertificateStore) Save(
	ctx context.Context,
	agentID string,
	cert *domain.ByocServerCertificate,
) error {
	sansJSON, err := json.Marshal(cert.SubjectAlternativeNames)
	if err != nil {
		return err
	}
	chain := sql.NullString{}
	if cert.ChainCertificatesPEM != "" {
		chain = sql.NullString{String: cert.ChainCertificatesPEM, Valid: true}
	}
	const q = `
        INSERT INTO byoc_certificates(
            agent_id, leaf_pem, chain_pem, cn, sans, issuer_dn,
            valid_from_ms, valid_to_ms, fingerprint, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.extx(ctx).ExecContext(ctx, q,
		agentID, cert.LeafCertificatePEM, chain, cert.SubjectCommonName,
		string(sansJSON), cert.IssuerDN,
		cert.ValidFromTimestamp.UnixMilli(), cert.ValidToTimestamp.UnixMilli(),
		cert.Fingerprint, time.Now().UnixMilli(),
	)
	return mapSQLErr(err)
}

// FindByAgentID returns all BYOC certificates for the agent, newest first.
func (s *ByocCertificateStore) FindByAgentID(
	ctx context.Context,
	agentID string,
) ([]*domain.ByocServerCertificate, error) {
	var rows []byocRow
	const q = `SELECT * FROM byoc_certificates WHERE agent_id = ? ORDER BY id DESC`
	if err := s.db.extx(ctx).SelectContext(ctx, &rows, q, agentID); err != nil {
		return nil, mapSQLErr(err)
	}
	out := make([]*domain.ByocServerCertificate, 0, len(rows))
	for _, r := range rows {
		c, err := r.toDomain()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// FindLatestValidByAgentID returns the most recently saved BYOC cert
// that is still within its validity period.
func (s *ByocCertificateStore) FindLatestValidByAgentID(
	ctx context.Context,
	agentID string,
) (*domain.ByocServerCertificate, error) {
	nowMs := time.Now().UnixMilli()
	var r byocRow
	const q = `
        SELECT * FROM byoc_certificates
        WHERE agent_id = ? AND valid_from_ms <= ? AND valid_to_ms > ?
        ORDER BY id DESC LIMIT 1`
	if err := s.db.extx(ctx).GetContext(ctx, &r, q, agentID, nowMs, nowMs); err != nil {
		return nil, mapSQLErr(err)
	}
	return r.toDomain()
}
