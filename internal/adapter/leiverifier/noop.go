// Package leiverifier provides the two port.LEIControlVerifier
// adapters behind the lei (vLEI) identifier kind:
//
//   - Noop     — zero-infra quickstart verifier; runs REAL Ed25519
//     crypto over the signing input but waives the GLEIF/vlei-verifier
//     authorization binding.
//   - Verifier — the real thing: a hardened HTTP client for an
//     internal vlei-verifier service (present / authorize / verify).
//
// Selected by `vlei.type` ("noop" | "verifier") in the RA config —
// the same pattern as the DNS verifier's `dns.type` ("noop" |
// "lookup") and the did:web resolver's `identity.resolver.type`
// ("noop" | "web").
package leiverifier

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// Noop is the quickstart vLEI verifier. It never dials anywhere.
//
// What this preserves and what it waives, stated precisely (the noop
// DNS / noop did:web precedent — real crypto, waived external-world
// binding):
//
//   - PRESERVED: VerifySignature runs a genuine Ed25519 verification
//     of the registrant's signature over the served signingInput, so
//     the sealed proof is not a rubber stamp. The subject AID encodes
//     the registrant's public key, so the verify key is recoverable
//     from the AID alone — no KEL, no state.
//   - WAIVED: "is this CESR really an authorized vLEI credential, and
//     is the AID↔LEI binding real?" Anyone can mint a keypair and
//     present any LEI. Authorization therefore returns Authorized
//     with an empty LEI (no binding asserted), and the service skips
//     the LEI-equality check accordingly.
//
// In noop mode the presentation `cesr` is a base64url (unpadded)
// encoding of a small JSON object {"publicKey": "<base64url 32-byte
// Ed25519 public key>", "lei": "<LEI>"}, and a signature is the
// base64url (unpadded) Ed25519 signature over the exact signingInput
// bytes. Strictly for local development and tests. NOT for production.
type Noop struct{}

// NewNoop returns the quickstart verifier.
func NewNoop() *Noop { return &Noop{} }

// noopPresentation is the noop's stand-in for a full-chain CESR export.
type noopPresentation struct {
	PublicKey string `json:"publicKey"`
	LEI       string `json:"lei"`
}

// Present decodes the noop presentation, recovers the registrant's
// Ed25519 public key, and reports a subject AID that IS the base64url
// encoding of that key (so VerifySignature can recover it). The LEI is
// echoed verbatim and the status is always AUTHORIZED.
func (n *Noop) Present(_ context.Context, cesr string) (port.PresentationResult, error) {
	pres, pub, err := decodeNoopPresentation(cesr)
	if err != nil {
		return port.PresentationResult{}, err
	}
	return port.PresentationResult{
		SubjectAID: base64.RawURLEncoding.EncodeToString(pub),
		LEI:        pres.LEI,
		Status:     "AUTHORIZED",
	}, nil
}

// Authorization always authorizes a well-formed AID and asserts NO
// LEI binding (the waived check) — the service treats the empty LEI
// as "verifier does not constrain the LEI".
func (n *Noop) Authorization(_ context.Context, subjectAID string) (port.AuthorizationResult, error) {
	if _, err := decodeSubjectAID(subjectAID); err != nil {
		return port.AuthorizationResult{}, err
	}
	return port.AuthorizationResult{Authorized: true, LEI: ""}, nil
}

// VerifySignature recovers the public key from the subject AID and
// runs a real Ed25519 verification of the signature over the
// signingInput bytes. A malformed AID or signature is a false (not an
// error) — a non-verifying proof, not an I/O failure.
func (n *Noop) VerifySignature(_ context.Context, subjectAID, signingInput, signature string) (bool, error) {
	pub, err := decodeSubjectAID(subjectAID)
	if err != nil {
		return false, nil //nolint:nilerr // malformed AID is a non-verifying proof (false), not an I/O failure
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, nil //nolint:nilerr // malformed signature is a non-verifying proof (false), not an I/O failure
	}
	return ed25519.Verify(pub, []byte(signingInput), sig), nil
}

// decodeNoopPresentation parses the base64url-wrapped JSON presentation
// and validates the embedded Ed25519 public key.
func decodeNoopPresentation(cesr string) (noopPresentation, ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cesr)
	if err != nil {
		return noopPresentation{}, nil, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation is not valid base64url")
	}
	var pres noopPresentation
	if err := json.Unmarshal(raw, &pres); err != nil {
		return noopPresentation{}, nil, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation is not a valid noop presentation object")
	}
	pub, err := decodeSubjectAID(pres.PublicKey)
	if err != nil {
		return noopPresentation{}, nil, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation publicKey is not a base64url Ed25519 public key")
	}
	if pres.LEI == "" {
		return noopPresentation{}, nil, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation carries no lei")
	}
	return pres, pub, nil
}

// decodeSubjectAID recovers the Ed25519 public key a noop subject AID
// encodes.
func decodeSubjectAID(aid string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(aid)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"subject AID is not a base64url Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// compile-time conformance.
var _ port.LEIControlVerifier = (*Noop)(nil)
