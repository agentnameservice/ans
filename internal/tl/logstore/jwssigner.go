package logstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/mod/sumdb/note"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
)

// JWSCheckpointSigner appends a standard-JWS signature line to every
// Tessera checkpoint. It implements tessera's `note.Signer` interface
// and is passed as an "additional signer" alongside the primary
// Ed25519 sumdb-note signer — the output checkpoint has both lines,
// one line per signer, matching the reference TL byte-for-byte.
//
// Reference: the reference TL's `TesseraJWSSigner` wires multiple
// `additionalSigners` into `WithCheckpointSigner`; we do the same.
//
// Note format refresher: the checkpoint body is
//
//	<origin>\n<size>\n<root-hash-base64>\n\n
//
// followed by one "— <origin> <base64-signature>" line per signer.
// The base64 prefix of each signature line encodes a 4-byte
// keyhash that verifiers use to route to the right signer.
// Tessera builds the line; our Sign just needs to return the
// signature bytes that get base64-encoded after the keyhash prefix.
type JWSCheckpointSigner struct {
	km     port.KeyManager
	keyID  string
	pub    *ecdsa.PublicKey
	origin string
	// keyhash is the 4-byte SHA-256(SPKI-DER) prefix used both as
	// the `kid` value in the JWS header and as the signature-line
	// key-hash prefix in the checkpoint note. Computed once at
	// construction — it's deterministic per key.
	keyhash uint32
	nowFn   func() int64
}

// NewJWSCheckpointSigner builds a JWSCheckpointSigner backed by the
// given KeyManager. Origin must match the checkpoint's origin line
// (Tessera requires every signer's Name() to match). The key should
// be ECDSA P-256 — the JWS alg is fixed at ES256.
func NewJWSCheckpointSigner(
	ctx context.Context,
	km port.KeyManager,
	keyID, origin string,
) (*JWSCheckpointSigner, error) {
	if km == nil {
		return nil, errors.New("logstore: KeyManager required")
	}
	if origin == "" {
		return nil, errors.New("logstore: origin required")
	}
	pubAny, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("logstore: fetch pubkey %q: %w", keyID, err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("logstore: key %q is not ECDSA (type %T)", keyID, pubAny)
	}
	hashBytes, err := anscrypto.SPKIKeyHash4(pub)
	if err != nil {
		return nil, fmt.Errorf("logstore: compute key hash: %w", err)
	}
	return &JWSCheckpointSigner{
		km:      km,
		keyID:   keyID,
		pub:     pub,
		origin:  origin,
		keyhash: binary.BigEndian.Uint32(hashBytes),
		nowFn:   func() int64 { return 0 }, // overridden in production by WithClock
	}, nil
}

// WithClock overrides the timestamp source — used by tests to pin
// the JWS `timestamp` claim for deterministic fixtures.
func (s *JWSCheckpointSigner) WithClock(fn func() int64) *JWSCheckpointSigner {
	s.nowFn = fn
	return s
}

// Name implements note.Signer. Must equal the checkpoint origin for
// Tessera to accept the signer — both signature lines end up
// prefixed with `— <origin>`.
func (s *JWSCheckpointSigner) Name() string { return s.origin }

// KeyHash implements note.Signer. Returns the 4-byte SHA-256 prefix
// of SPKI-DER as a uint32 — same hash the reference uses, same hash
// stamped into the JWS `kid` header so verifiers can link the
// signature line to the `kid`.
func (s *JWSCheckpointSigner) KeyHash() uint32 { return s.keyhash }

// Sign implements note.Signer. Tessera hands us the full checkpoint
// body (`<origin>\n<size>\n<root-hash-base64>\n\n`). We parse it
// into the structured fields a JWS verifier will recompute, sign the
// JCS-canonical JSON of those fields as a *standard* JWS (not
// detached — the body is embedded so verifiers know what was signed),
// and return the JWS compact-form bytes. Tessera then base64-encodes
// those bytes into the signature line it appends to the checkpoint.
//
// Matches the reference TL's `TesseraJWSSigner.SignTreeHead`: same
// payload shape, same alg (ES256), same checkpointFormat tag.
func (s *JWSCheckpointSigner) Sign(msg []byte) ([]byte, error) {
	size, rootHash, origin, err := parseCheckpointBody(msg)
	if err != nil {
		return nil, err
	}
	if origin != s.origin {
		return nil, fmt.Errorf("logstore: checkpoint origin %q != signer origin %q",
			origin, s.origin)
	}

	payload := map[string]any{
		"origin":           origin,
		"treesize":         size,
		"rootHash":         rootHash,
		"timestamp":        s.nowFn(),
		"checkpointFormat": "c2sp/v1",
	}

	jwsCompact, err := anscrypto.SignStandardJWS(context.Background(),
		s.km, s.keyID,
		anscrypto.JWSProtectedHeader{
			Typ:       "JWT",
			Kid:       anscrypto.OpaqueKeyIDFromHash(s.keyhash),
			Timestamp: s.nowFn(),
		},
		payload)
	if err != nil {
		return nil, fmt.Errorf("logstore: sign checkpoint JWS: %w", err)
	}
	return []byte(jwsCompact), nil
}

// parseCheckpointBody pulls out (size, rootHashB64, origin) from a
// Tessera-format checkpoint body. Format:
//
//	<origin>\n<size>\n<root-hash-base64>\n\n
//
// The trailing double-newline marks the end of the body; signature
// lines follow it but Tessera passes us only the body here.
func parseCheckpointBody(body []byte) (int64, string, string, error) {
	// Trim trailing blank-line delimiter if present so the split
	// behaves for bodies Tessera hands us with or without it.
	body = bytes.TrimRight(body, "\n")
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) < 3 {
		return 0, "", "", fmt.Errorf("logstore: checkpoint body has %d lines, want ≥3", len(lines))
	}
	origin := string(lines[0])
	size, err := strconv.ParseInt(string(lines[1]), 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("logstore: parse tree size %q: %w", lines[1], err)
	}
	// root hash is on line 2; it's already base64-encoded text (no
	// need to decode — we re-emit it into the JWS payload verbatim
	// so verifiers can reconstruct the same string).
	if _, berr := base64.StdEncoding.DecodeString(string(lines[2])); berr != nil {
		return 0, "", "", fmt.Errorf("logstore: root hash not base64: %w", berr)
	}
	rootHash := string(lines[2])
	return size, rootHash, origin, nil
}

// Compile-time check that we satisfy note.Signer.
var _ note.Signer = (*JWSCheckpointSigner)(nil)
