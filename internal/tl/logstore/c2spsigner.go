// Package logstore wraps the Tessera transparency-log appender plus
// its checkpoint signers. This file holds the C2SP ECDSA signer.
package logstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/note"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// C2SPECDSASigner is a note.Signer that produces a C2SP-compliant
// ECDSA P-256 signature over the raw checkpoint body. It is the
// primary Tessera checkpoint signer — Tessera calls Sign(msg) with
// the note body, prepends the 4-byte KeyHash to whatever bytes we
// return, base64-encodes the combined blob, and writes it as the
// `— <origin> <base64>` signature line.
//
// Sign(msg) returns an ASN.1 DER ECDSA signature over
// SHA-256(msg). The wire shape on the checkpoint note is therefore:
//
//	<keyhash:4> || <ecdsa-der-sig>
//
// which is exactly what the production TL emits.
//
// Mirrors the reference's sigstore.LoadSigner /
// `merkle.TesseraJWSSigner`'s primary signer, minus the KMS
// dependency — we sign via the pluggable port.KeyManager so the
// same code path works against file-backed and cloud-KMS adapters.
type C2SPECDSASigner struct {
	km      port.KeyManager
	keyID   string
	pub     *ecdsa.PublicKey
	origin  string
	keyhash uint32
}

// NewC2SPECDSASigner builds a C2SPECDSASigner against the given
// ECDSA P-256 key. Origin must match the checkpoint's origin line;
// Tessera rejects signers whose Name() diverges from the body.
func NewC2SPECDSASigner(ctx context.Context, km port.KeyManager, keyID, origin string) (*C2SPECDSASigner, error) {
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
	return &C2SPECDSASigner{
		km:      km,
		keyID:   keyID,
		pub:     pub,
		origin:  origin,
		keyhash: binary.BigEndian.Uint32(hashBytes),
	}, nil
}

// PublicKey exposes the ECDSA public key used by the signer — the
// checkpoint-read path needs this to re-verify the primary signature
// at response time.
func (s *C2SPECDSASigner) PublicKey() *ecdsa.PublicKey { return s.pub }

// Name implements note.Signer.
func (s *C2SPECDSASigner) Name() string { return s.origin }

// KeyHash implements note.Signer. Matches the reference TL's
// `SHA-256(SPKI-DER)[0:4]` formula so the keyhash on the checkpoint
// signature line agrees with the one advertised on /root-keys.
func (s *C2SPECDSASigner) KeyHash() uint32 { return s.keyhash }

// Sign implements note.Signer. Returns ASN.1 DER ECDSA signature
// bytes over SHA-256(msg) — no JWS framing, no extra envelope. The
// note package prepends the 4-byte keyhash before writing the
// checkpoint signature line. The verifier recomputes SHA-256 over
// the same body bytes and verifies against the key advertised at
// /root-keys.
func (s *C2SPECDSASigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	rawSig, err := s.km.Sign(context.Background(), s.keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("logstore: c2sp sign: %w", err)
	}
	return rawSig, nil
}

// Compile-time check that C2SPECDSASigner satisfies note.Signer.
var _ note.Signer = (*C2SPECDSASigner)(nil)
