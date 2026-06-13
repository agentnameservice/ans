package port

import "context"

// PresentationResult is what a vLEI presentation yields once the
// verifier has parsed the full-chain CESR export: the holder's subject
// AID (derived FROM the presentation, never caller-asserted — the
// §3.6 pinning rule), the credential's authorized LEI, and the
// verifier's register-time authorization status.
//
// Status is advisory: it records what the verifier saw at present
// time. The authoritative gate is the LIVE Authorization re-check at
// verify-control — a credential may age out of authorization (the
// vlei-verifier's TimeoutAuth window) between register and prove.
type PresentationResult struct {
	// SubjectAID is the holder AID the verifier extracted from the
	// presentation. The RA pins it on the identity aggregate; the
	// caller never supplies it.
	SubjectAID string
	// LEI is the LEI the presented credential authorizes the AID for.
	LEI string
	// Status is "AUTHORIZED" or "PENDING".
	Status string
}

// AuthorizationResult is the verifier's LIVE view of an AID's vLEI
// authorization at verify-control time.
type AuthorizationResult struct {
	// Authorized reports whether the AID currently holds a valid,
	// unexpired vLEI authorization.
	Authorized bool
	// LEI is the authorized LEI, when the verifier asserts one. The
	// noop adapter waives the AID↔LEI binding and returns "" — the
	// service then skips the LEI-equality assertion (the documented
	// noop waiver, mirroring noop-DNS waiving the zone binding).
	LEI string
}

// LEIControlVerifier is the outbound port for the GLEIF / vlei-verifier
// interaction behind the lei (vLEI) identifier kind. lei is NOT a DID
// method, so it does not ride port.DIDResolver; it gets its own port,
// following the DNS/DID precedent — a noop adapter for the quickstart
// and a real adapter selected by config (`vlei.type: noop | verifier`).
//
// The real verifier owns all KERI key state: it is the authoritative
// key-state oracle. Present reports the subject AID, Authorization
// re-checks live authorization, and VerifySignature owns the KEL/key
// state used to check the registrant's signature. The noop quickstart
// adapter reads only the leaf credential's subject AID (a credential
// attribute, not key state) and waives the authorization + signature
// checks — the DNS/did:web noop precedent.
type LEIControlVerifier interface {
	// Present submits the full-chain CESR export to the verifier and
	// returns the parsed subject AID + authorized LEI + presentation
	// status. The subject AID is derived from the presentation, never
	// caller-asserted.
	Present(ctx context.Context, cesr string) (PresentationResult, error)

	// Authorization reports the verifier's LIVE authorization for the
	// AID (re-checked on every verify-control; the register-time
	// status is advisory).
	Authorization(ctx context.Context, subjectAID string) (AuthorizationResult, error)

	// VerifySignature checks that `signature` over `signingInput` was
	// produced by the AID's current signing key (the verifier owns the
	// KEL/key state); an error signals an
	// I/O or protocol failure reaching the verifier.
	VerifySignature(ctx context.Context, subjectAID, signingInput, signature string) (bool, error)
}
