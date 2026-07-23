// Package leiverifier provides the two port.LEIControlVerifier
// adapters behind the lei (vLEI) identifier kind:
//
//   - Noop     — zero-infra quickstart verifier; accepts the SAME
//     full-chain CESR presentation the real verifier does, pins the real
//     subject AID, and waives the external-world bindings (GLEIF
//     authorization + cryptographic signature check).
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

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// Noop is the quickstart vLEI verifier. It never dials anywhere.
//
// It consumes the SAME client payload as the real verifier — the
// full-chain CESR export (`vleiPresentation.cesr`) and a qb64 CESR
// signature (`cesrSignature`) — so a registration that works in
// verifier mode works unchanged in noop mode. This is the DNS / did:web
// noop precedent: the client sends identical bytes in either mode, and
// the noop derives its answer from material already in the request.
//
// What this preserves and what it waives, stated precisely:
//
//   - PRESERVED: the presentation is a real full-chain CESR export and
//     the pinned subject AID is the real holder AID read from the
//     presented leaf credential (`a.i`) — so the sealed identity carries
//     the genuine KERI AID, and the register-time LEI echoed from the
//     credential (`a.LEI`) lets the service check it against the claimed
//     value (a structural string compare, no external oracle).
//   - WAIVED: "is this an authorized vLEI credential, is the AID↔LEI
//     binding real, and does the signature verify against the AID's
//     current key?" The quickstart has no KEL key-state oracle, so —
//     like the noop DNS verifier, which accepts any well-formed record
//     without proving the live zone — it accepts a well-formed qb64
//     signature without a cryptographic check, authorizes any
//     well-formed AID, and asserts no live LEI binding (empty LEI).
//
// Strictly for local development and tests. NOT for production.
type Noop struct{}

// NewNoop returns the quickstart verifier.
func NewNoop() *Noop { return &Noop{} }

// Present reads the presented (leaf) credential from the full-chain
// CESR export, pins its subject AID (`a.i`) as the holder AID, echoes
// the credential's claimed LEI (`a.LEI`), and always reports AUTHORIZED.
// It reads credential attributes only — never KERI key state.
func (n *Noop) Present(_ context.Context, cesr string) (port.PresentationResult, error) {
	leaf, ok := leafFrame(cesr)
	if !ok {
		return port.PresentationResult{}, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation carries no ACDC credential")
	}
	if !isQB64(leaf.A.I) {
		return port.PresentationResult{}, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"the presented credential carries no valid subject AID")
	}
	return port.PresentationResult{
		SubjectAID: leaf.A.I,
		LEI:        leaf.A.LEI,
		Status:     port.StatusAuthorized,
	}, nil
}

// Authorization authorizes any well-formed (qb64) AID and asserts NO
// live LEI binding (the waived check) — the service treats the empty LEI
// as "verifier does not constrain the LEI". A non-qb64 AID is a
// validation error, mirroring the real verifier's guard.
func (n *Noop) Authorization(_ context.Context, subjectAID string) (port.AuthorizationResult, error) {
	if !isQB64(subjectAID) {
		return port.AuthorizationResult{}, domain.NewValidationError("LEI_SUBJECT_AID_INVALID",
			"subject AID is not a valid qb64 identifier")
	}
	return port.AuthorizationResult{Authorized: true, LEI: ""}, nil
}

// VerifySignature is a structural check only: the quickstart has no KEL
// key-state oracle to resolve the AID's current key, so it accepts a
// well-formed qb64 signature over the well-formed AID and rejects a
// malformed one. A malformed AID or signature is a non-verifying false
// (not an I/O error) — the waived binding, the noop DNS precedent.
func (n *Noop) VerifySignature(_ context.Context, subjectAID, _, signature string) (bool, error) {
	return isQB64(subjectAID) && isQB64(signature), nil
}

// compile-time conformance.
var _ port.LEIControlVerifier = (*Noop)(nil)
