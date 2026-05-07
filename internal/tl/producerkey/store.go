// Package producerkey holds the trust store the Transparency Log uses
// to verify incoming event signatures.
//
// A "producer" in ANS terminology is a Registration Authority — the
// thing that signs events before POSTing them to the TL. The TL
// maintains a keyed-by-(raId, keyId) map of producer public keys. On
// every append, the TL parses the X-Signature header's JWS protected
// header, looks up the matching PEM here, and verifies the signature
// before accepting the event.
//
// Stage 1 shipped an in-memory Store loaded from YAML; Stage 4 adds a
// SQLite-backed Store with admin CRUD routes so keys can be rotated at
// runtime. The narrow verifier interface (`Store`) is unchanged: both
// backends satisfy it so the ingest path is backend-agnostic. The
// fatter admin surface (`AdminStore`) only the SQLite backend satisfies.
package producerkey

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Store.Get when no producer key matches.
var ErrNotFound = errors.New("producerkey: not found")

// ErrDuplicateKey is returned when attempting to register a key whose
// keyID already exists. Admin handlers map this to 409 Conflict.
var ErrDuplicateKey = errors.New("producerkey: duplicate key_id")

// ErrInvalidRange is returned when validFrom >= expiresAt on a new
// registration. Admin handlers map this to 422.
var ErrInvalidRange = errors.New("producerkey: validFrom must be before expiresAt")

// Store is the producer-key *verifier* surface — the only interface
// the TL's event-ingest path depends on. Both the in-memory and
// SQLite backends satisfy this; admin CRUD lives on the wider
// AdminStore interface which only the SQLite backend implements.
type Store interface {
	// Get returns the PEM-encoded public key for the given (raID, keyID)
	// pair. Returns ErrNotFound if no matching active key exists, or
	// if the matching key is revoked or outside its validity window.
	//
	// The lookup is by (raID, keyID) rather than keyID alone because
	// the reference TL scopes keys to producers — two RAs with the
	// same keyId string are two different keys.
	Get(ctx context.Context, raID, keyID string) (pemEncoded string, err error)
}

// Entry is the shape producer keys take on registration — the inputs
// a caller supplies when creating a new key. The in-memory Store only
// cares about the core four (raID, keyID, algorithm, PEM) and ignores
// the time-window + metadata fields; the SQLite store persists all.
type Entry struct {
	RaID         string
	KeyID        string
	Algorithm    string // "ES256" (only supported algorithm today; matches JWS header alg).
	PublicKeyPEM string

	// ValidFrom and ExpiresAt bound the window during which the
	// verifier will accept signatures with this key. Both are in the
	// registration-time zone (unix millis when persisted). Zero
	// values are accepted by the in-memory store (which ignores
	// time bounds) but rejected by the SQLite store.
	ValidFrom time.Time
	ExpiresAt time.Time

	// Metadata is optional free-form JSON — reference uses
	// {environment, region, rotation_of}. Stored verbatim; the TL
	// never reads it.
	Metadata []byte // raw JSON, nil if none
}

// Record is the full database row returned by AdminStore list/get
// operations. Includes fields the caller doesn't set on registration
// (Status, Fingerprint, CreatedAt, UpdatedAt, RevokedAt) plus the
// optional C2SP opaque identifiers.
type Record struct {
	Entry

	Fingerprint  string    // "SHA256:<hex>" of SPKI DER.
	Status       string    // "active" or "revoked".
	CreatedAt    time.Time // row creation time.
	UpdatedAt    time.Time // last mutation (status change, rotation).
	RevokedAt    time.Time // zero unless Status == "revoked".
	RevokesKeyID string    // empty unless the key was created as a rotation.
	KeyIDOpaque  string    // C2SP 8-hex-char opaque kid; empty if not generated.
	RaIDOpaque   string    // opaque raId; empty if not generated.
}

// AdminStore is the producer-key admin surface — CRUD used by the
// /internal/v1/producer-keys routes. The SQLite backend is authoritative;
// the in-memory backend does not implement this. A store that
// satisfies AdminStore also satisfies Store.
type AdminStore interface {
	Store

	// Register inserts a new producer key. Returns ErrDuplicateKey if
	// the KeyID already exists, ErrInvalidRange if ValidFrom >=
	// ExpiresAt. On success the returned Record includes the fields
	// the store populated (Fingerprint, Status="active", CreatedAt).
	Register(ctx context.Context, e Entry) (*Record, error)

	// Revoke marks the key as revoked and stamps RevokedAt.
	// Subsequent Get calls return ErrNotFound. Returns ErrNotFound if
	// the key doesn't exist or was already revoked.
	Revoke(ctx context.Context, keyID string) error

	// GetByKeyID returns the full record for a specific key_id,
	// regardless of status. Used by the admin GET-by-id path.
	GetByKeyID(ctx context.Context, keyID string) (*Record, error)

	// ListByRAID returns every producer key registered for the given
	// raID, newest (by valid_from) first. Includes revoked keys so
	// admins can audit history; callers filter by status if they
	// only want active keys.
	ListByRAID(ctx context.Context, raID string) ([]*Record, error)
}
