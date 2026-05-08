package sqlitetl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/godaddy/ans/internal/tl/producerkey"
)

// ProducerKeyStore is a SQLite-backed producer-key trust store.
//
// Implements both the narrow verifier interface (`producerkey.Store`)
// used by the TL ingest path and the wider admin interface
// (`producerkey.AdminStore`) used by /internal/v1/producer-keys. Time
// semantics: every time column is unix milliseconds. The verifier
// checks `NOW() BETWEEN valid_from_ms AND expires_at_ms` and status ==
// 'active'; revocation sets status and revoked_at_ms atomically.
//
// A Clock is injectable for deterministic tests. Prod uses time.Now.
type ProducerKeyStore struct {
	db    *DB
	clock func() time.Time
}

// NewProducerKeyStore constructs a ProducerKeyStore on the shared DB.
func NewProducerKeyStore(db *DB) *ProducerKeyStore {
	return &ProducerKeyStore{db: db, clock: time.Now}
}

// WithClock replaces the clock — used by tests to freeze time so the
// validFrom/expiresAt filters produce deterministic outputs. Returns
// the receiver for fluent use.
func (s *ProducerKeyStore) WithClock(fn func() time.Time) *ProducerKeyStore {
	s.clock = fn
	return s
}

// Get implements producerkey.Store — the hot path called on every
// event append. Filters to status='active' within the validity
// window; anything else is indistinguishable from "no such key" to
// the caller (which maps to 422 NOT_FOUND_PRODUCER_KEY). We do NOT
// leak "the key is revoked" / "the key is expired" as separate
// signals here because the ingest path's error model only has
// "trusted" vs "not trusted".
func (s *ProducerKeyStore) Get(ctx context.Context, raID, keyID string) (string, error) {
	nowMs := s.clock().UnixMilli()
	var pem string
	err := s.db.db.GetContext(ctx, &pem, `
        SELECT public_key_pem FROM tl_producer_keys
        WHERE ra_id = ?
          AND key_id = ?
          AND status = 'active'
          AND valid_from_ms <= ?
          AND expires_at_ms > ?`,
		raID, keyID, nowMs, nowMs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", producerkey.ErrNotFound
		}
		return "", err
	}
	return pem, nil
}

// Register implements producerkey.AdminStore.
//
// Validation:
//   - RaID, KeyID, Algorithm, PublicKeyPEM required (empty string
//     rejected) — cheap checks before hitting SQLite.
//   - ValidFrom must be strictly before ExpiresAt.
//   - PublicKeyPEM is parsed to derive the SHA-256 fingerprint. A
//     malformed PEM or a non-public-key DER triggers a validation
//     error — this also rules out PEMs with private key material
//     being pasted into the trust store by mistake.
//
// On duplicate KeyID SQLite raises a UNIQUE constraint error which
// we unwrap into ErrDuplicateKey so the handler can return 409.
func (s *ProducerKeyStore) Register(ctx context.Context, e producerkey.Entry) (*producerkey.Record, error) {
	if err := validateEntry(e); err != nil {
		return nil, err
	}
	fp, err := fingerprintFromPEM(e.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("producerkey: %w", err)
	}

	nowMs := s.clock().UnixMilli()
	var metadata any
	if len(e.Metadata) > 0 {
		metadata = string(e.Metadata) // CHECK json_valid runs in SQLite
	} else {
		metadata = nil
	}

	_, err = s.db.db.ExecContext(ctx, `
        INSERT INTO tl_producer_keys(
            key_id, ra_id, algorithm, public_key_pem, fingerprint,
            status, valid_from_ms, expires_at_ms,
            metadata, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
		e.KeyID, e.RaID, e.Algorithm, e.PublicKeyPEM, fp,
		e.ValidFrom.UnixMilli(), e.ExpiresAt.UnixMilli(),
		metadata, nowMs, nowMs)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return nil, producerkey.ErrDuplicateKey
		}
		return nil, fmt.Errorf("producerkey: insert: %w", err)
	}

	return s.GetByKeyID(ctx, e.KeyID)
}

// Revoke marks a key as revoked. No-op on already-revoked keys is
// deliberately rejected with ErrNotFound — admins should only see a
// successful revocation for a live key, otherwise the response would
// mask a typo in the key_id.
func (s *ProducerKeyStore) Revoke(ctx context.Context, keyID string) error {
	nowMs := s.clock().UnixMilli()
	res, err := s.db.db.ExecContext(ctx, `
        UPDATE tl_producer_keys
        SET status = 'revoked',
            revoked_at_ms = ?,
            updated_at_ms = ?
        WHERE key_id = ? AND status = 'active'`,
		nowMs, nowMs, keyID)
	if err != nil {
		return fmt.Errorf("producerkey: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("producerkey: rows affected: %w", err)
	}
	if n == 0 {
		return producerkey.ErrNotFound
	}
	return nil
}

// GetByKeyID returns the full row for a key_id, regardless of status.
// Admin handlers use this for the POST-response-body path.
func (s *ProducerKeyStore) GetByKeyID(ctx context.Context, keyID string) (*producerkey.Record, error) {
	var row producerKeyRow
	err := s.db.db.GetContext(ctx, &row, `
        SELECT key_id, ra_id, algorithm, public_key_pem, fingerprint,
               status, valid_from_ms, expires_at_ms,
               revoked_at_ms, revokes_key_id,
               metadata, key_id_opaque, ra_id_opaque,
               created_at_ms, updated_at_ms
        FROM tl_producer_keys
        WHERE key_id = ?`, keyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, producerkey.ErrNotFound
		}
		return nil, err
	}
	return row.toRecord(), nil
}

// ListByRAID returns every producer key for raID. Ordered newest
// valid_from first so admins see current keys at the top; revoked
// keys show up too (filterable client-side) to support audit.
func (s *ProducerKeyStore) ListByRAID(ctx context.Context, raID string) ([]*producerkey.Record, error) {
	var rows []producerKeyRow
	err := s.db.db.SelectContext(ctx, &rows, `
        SELECT key_id, ra_id, algorithm, public_key_pem, fingerprint,
               status, valid_from_ms, expires_at_ms,
               revoked_at_ms, revokes_key_id,
               metadata, key_id_opaque, ra_id_opaque,
               created_at_ms, updated_at_ms
        FROM tl_producer_keys
        WHERE ra_id = ?
        ORDER BY valid_from_ms DESC, created_at_ms DESC`, raID)
	if err != nil {
		return nil, err
	}
	out := make([]*producerkey.Record, len(rows))
	for i := range rows {
		out[i] = rows[i].toRecord()
	}
	return out, nil
}

// ----- row type -----

type producerKeyRow struct {
	KeyID        string         `db:"key_id"`
	RaID         string         `db:"ra_id"`
	Algorithm    string         `db:"algorithm"`
	PublicKeyPEM string         `db:"public_key_pem"`
	Fingerprint  string         `db:"fingerprint"`
	Status       string         `db:"status"`
	ValidFromMs  int64          `db:"valid_from_ms"`
	ExpiresAtMs  int64          `db:"expires_at_ms"`
	RevokedAtMs  sql.NullInt64  `db:"revoked_at_ms"`
	RevokesKeyID sql.NullString `db:"revokes_key_id"`
	Metadata     sql.NullString `db:"metadata"`
	KeyIDOpaque  sql.NullString `db:"key_id_opaque"`
	RaIDOpaque   sql.NullString `db:"ra_id_opaque"`
	CreatedAtMs  int64          `db:"created_at_ms"`
	UpdatedAtMs  int64          `db:"updated_at_ms"`
}

func (r *producerKeyRow) toRecord() *producerkey.Record {
	rec := &producerkey.Record{
		Entry: producerkey.Entry{
			RaID:         r.RaID,
			KeyID:        r.KeyID,
			Algorithm:    r.Algorithm,
			PublicKeyPEM: r.PublicKeyPEM,
			ValidFrom:    time.UnixMilli(r.ValidFromMs),
			ExpiresAt:    time.UnixMilli(r.ExpiresAtMs),
		},
		Fingerprint: r.Fingerprint,
		Status:      r.Status,
		CreatedAt:   time.UnixMilli(r.CreatedAtMs),
		UpdatedAt:   time.UnixMilli(r.UpdatedAtMs),
	}
	if r.Metadata.Valid {
		rec.Metadata = []byte(r.Metadata.String)
	}
	if r.RevokedAtMs.Valid {
		rec.RevokedAt = time.UnixMilli(r.RevokedAtMs.Int64)
	}
	if r.RevokesKeyID.Valid {
		rec.RevokesKeyID = r.RevokesKeyID.String
	}
	if r.KeyIDOpaque.Valid {
		rec.KeyIDOpaque = r.KeyIDOpaque.String
	}
	if r.RaIDOpaque.Valid {
		rec.RaIDOpaque = r.RaIDOpaque.String
	}
	return rec
}

// ----- helpers -----

// validateEntry runs cheap pre-DB validation on a registration.
// Anything that can be rejected without touching SQLite lives here.
func validateEntry(e producerkey.Entry) error {
	if e.RaID == "" {
		return fmt.Errorf("%w: raId required", producerkey.ErrInvalidRange)
	}
	if e.KeyID == "" {
		return fmt.Errorf("%w: keyId required", producerkey.ErrInvalidRange)
	}
	if e.Algorithm == "" {
		return fmt.Errorf("%w: algorithm required", producerkey.ErrInvalidRange)
	}
	if e.PublicKeyPEM == "" {
		return fmt.Errorf("%w: publicKeyPem required", producerkey.ErrInvalidRange)
	}
	if e.ValidFrom.IsZero() || e.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: validFrom and expiresAt required", producerkey.ErrInvalidRange)
	}
	if !e.ValidFrom.Before(e.ExpiresAt) {
		return producerkey.ErrInvalidRange
	}
	return nil
}

// fingerprintFromPEM parses a PEM-wrapped SPKI public key and returns
// the SHA-256 fingerprint in the project's standard
// `SHA256:<hex>` form. Rejects PEMs whose inner DER won't parse as a
// public key — that's the standard way to catch a paste-the-private-
// key-by-accident bug before it lands in the trust store.
func fingerprintFromPEM(pubPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return "", errors.New("publicKeyPem: not a valid PEM block")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return "", fmt.Errorf("publicKeyPem: parse SPKI: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return "SHA256:" + hex.EncodeToString(sum[:]), nil
}
