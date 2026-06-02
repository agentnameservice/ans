// Package cose implements the COSE_Sign1 wire-format primitive
// (RFC 9052 §4.2, formerly RFC 8152) used by every signed object in
// the ANS stack: SCITT transparency-log receipts (internal/tl/receipt),
// status tokens (internal/tl/receipt), and bundled agent attestations
// (internal/ra/service).
//
// Why this is its own package: the wire shape is identical across the
// three call sites — protected header bytes, unprotected header map,
// attached payload, ECDSA P-256 signature in IEEE P1363 form, wrapped
// in CBOR tag 18 — and we want the byte-layout invariant to live in
// exactly one place so a wire-format change to one signed object can't
// silently diverge another. Header label values and the verifiable-
// data-structure encoding are caller responsibilities; this package
// only owns the COSE_Sign1 envelope.
//
// Encoding is CBOR-deterministic per RFC 8949 §4.2 (the
// "core-deterministic" profile fxamacker/cbor exposes as
// CoreDetEncOptions). Two calls with the same inputs produce the same
// envelope bytes — modulo the ECDSA signature itself, which is
// non-deterministic.
package cose

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// Signer produces an ECDSA P-256 signature in IEEE P1363 form over
// SHA-256(msg). The conversion from the ASN.1 DER signature that
// port.KeyManager returns is the signer's responsibility — see
// KeyManagerSigner for the canonical implementation.
//
// The interface is taken (rather than a *KeyManagerSigner directly)
// so tests can substitute a deterministic signer and so future
// hardware-backed signers can plug in at this seam without touching
// the COSE wire-format code.
type Signer interface {
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// KeyManagerSigner adapts a port.KeyManager into a Signer by hashing
// the message with SHA-256, asking the key manager to sign the
// digest (which returns ASN.1 DER), and converting to IEEE P1363
// (RFC 8152 §8.1).
type KeyManagerSigner struct {
	km    port.KeyManager
	keyID string
}

// NewKeyManagerSigner wraps a port.KeyManager. The keyID must be an
// ECDSA P-256 key the manager can sign with; this constructor does
// NOT verify that — callers are expected to have already resolved
// the key once at startup (e.g. via km.GetPublicKey) to surface
// configuration errors with full context.
func NewKeyManagerSigner(km port.KeyManager, keyID string) (*KeyManagerSigner, error) {
	if km == nil {
		return nil, errors.New("cose: key manager required")
	}
	if keyID == "" {
		return nil, errors.New("cose: keyID required")
	}
	return &KeyManagerSigner{km: km, keyID: keyID}, nil
}

// Sign implements Signer.
func (s *KeyManagerSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	der, err := s.km.Sign(ctx, s.keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("cose: key manager sign: %w", err)
	}
	p1363, err := anscrypto.DERToP1363(der, 32) // P-256 coord size
	if err != nil {
		return nil, fmt.Errorf("cose: DER→P1363: %w", err)
	}
	return p1363, nil
}

// Sign1 builds a COSE_Sign1 (RFC 9052 §4.2) over the given payload.
//
// Inputs:
//
//   - protected: integer-keyed map of header parameters that belong
//     in the protected (signed) header. Encoded with CBOR
//     core-deterministic options before being included in the
//     Sig_structure. Pass nil for an empty protected header (encoded
//     as bstr(h”) per RFC 9052 §3).
//   - unprotected: integer-keyed map of header parameters that
//     belong in the unprotected header. Encoded as-is. Pass nil for
//     no unprotected parameters; an empty map is emitted on the wire.
//   - payload: the attached payload bytes. Detached payloads (nil
//     in the COSE_Sign1, supplied separately at verify time) are
//     not currently supported by any ANS signer.
//
// Output is the CBOR tag-18 wrapped COSE_Sign1 ready for transmission.
//
// The Sig_structure is RFC 9052 §4.4:
//
//	Sig_structure = [
//	  context : "Signature1",
//	  body_protected : bstr,
//	  external_aad : bstr,            -- empty (no AAD in any ANS use)
//	  payload : bstr,
//	]
func Sign1(
	ctx context.Context,
	signer Signer,
	protected, unprotected map[int]any,
	payload []byte,
) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("cose: signer required")
	}
	if len(payload) == 0 {
		return nil, errors.New("cose: payload required (detached payloads not supported)")
	}

	protectedBytes, err := encodeProtectedHeader(protected)
	if err != nil {
		return nil, fmt.Errorf("cose: encode protected header: %w", err)
	}

	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad — empty
		payload,
	}
	sigStructureBytes, err := detMarshal(sigStructure)
	if err != nil {
		// SAFETY: unreachable. sigStructure is a fixed 4-element
		// []any of [string, []byte, []byte, []byte] — all primitives
		// CoreDet encodes without error. The only way detMarshal
		// errors is on an unencodable user type, and we control
		// every element of this slice locally.
		return nil, fmt.Errorf("cose: encode Sig_structure: %w", err)
	}

	sig, err := signer.Sign(ctx, sigStructureBytes)
	if err != nil {
		return nil, fmt.Errorf("cose: sign: %w", err)
	}

	// COSE_Sign1 = [ protected:bstr, unprotected:map, payload:bstr, signature:bstr ]
	unprotectedOut := unprotected
	if unprotectedOut == nil {
		unprotectedOut = map[int]any{}
	}
	coseArray := []any{
		protectedBytes,
		unprotectedOut,
		payload,
		sig,
	}
	tagged := cbor.Tag{Number: 18, Content: coseArray}
	out, err := detMarshal(tagged)
	if err != nil {
		// SAFETY: unreachable. coseArray is [bstr, map[int]any, bstr,
		// bstr] — primitives and an integer-keyed map whose values
		// the caller already passed through detMarshal once
		// successfully (via the protected-header encode at the top
		// of this function). The unprotected map is the only fresh
		// surface, and unencodable values there would already have
		// been caught by the protected-header encode if the caller
		// is consistent in what they pass in. Belt-and-suspenders.
		return nil, fmt.Errorf("cose: encode COSE_Sign1: %w", err)
	}
	return out, nil
}

// encodeProtectedHeader returns the CBOR byte string that becomes
// the COSE_Sign1's first element. Per RFC 9052 §3, an empty
// protected-header map is encoded as a zero-length bstr (h”), not
// as bstr(CBOR(map{})). This is observable on the wire and matters
// for cross-implementation receipt verification.
func encodeProtectedHeader(m map[int]any) ([]byte, error) {
	if len(m) == 0 {
		return []byte{}, nil
	}
	return detMarshal(m)
}

// detMarshal encodes with CBOR core-deterministic options (RFC 8949
// §4.2): integer keys sorted by value, no indefinite lengths,
// smallest integer representations. Same encoder previously inlined
// in internal/tl/receipt; centralized here so every signed object
// in the stack shares it.
func detMarshal(v any) ([]byte, error) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		// SAFETY: unreachable. CoreDetEncOptions() returns a known-
		// valid options struct; EncMode() only errors when the
		// caller has mutated the options into an invalid state.
		// We don't mutate.
		return nil, err
	}
	return em.Marshal(v)
}
