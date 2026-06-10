package port

import (
	"context"
	"encoding/json"
)

// KeyHint is one kid → public-JWK pair the caller extracted from a
// submitted proof's protected header. Hints exist for the noop
// resolver (below); the web resolver ignores them.
type KeyHint struct {
	Kid          string
	PublicKeyJWK json.RawMessage
}

// DIDDocument is the subset of a resolved DID document the identity
// control proof needs: the document's id and its assertionMethod
// verification methods. Per DID Core, a key listed under
// assertionMethod is authorized to make assertions as the DID — key
// possession IS what DID control means.
type DIDDocument struct {
	ID              string
	AssertionMethod []VerificationMethod
}

// VerificationMethod is one assertionMethod entry. Exactly one of
// PublicKeyJwk / PublicKeyMultibase carries the key material.
//
// Raw is the verification-method object EXACTLY as the DID document
// served it — member-for-member, values untouched. Sealed identity
// events quote Raw verbatim: nothing derived, re-encoded, or
// normalized ever enters a seal. The typed fields beside it exist
// for the RA's checks (membership, controller, key parsing) only.
type VerificationMethod struct {
	ID                 string
	Controller         string
	Type               string
	PublicKeyJwk       json.RawMessage
	PublicKeyMultibase string
	Raw                json.RawMessage
}

// FindAssertionMethod returns the assertionMethod entry with the
// given id, or nil.
func (d *DIDDocument) FindAssertionMethod(kid string) *VerificationMethod {
	for i := range d.AssertionMethod {
		if d.AssertionMethod[i].ID == kid {
			return &d.AssertionMethod[i]
		}
	}
	return nil
}

// DIDResolver fetches the DID document for a did:web identifier — the
// authoritative key source for did:web control proofs. It is the only
// outbound I/O in the identity proof gate, which makes it the port:
//
//   - The "web" adapter performs a hardened HTTPS fetch (WebPKI,
//     SSRF dialer guards, timeout, size cap, bounded same-site
//     redirects) of the document at the DID's resolution URL. Hints
//     are ignored — the resolved document is always the key source.
//
//   - The "noop" adapter performs no I/O and synthesizes a document
//     from the hints (the kid → JWK pairs embedded in the submitted
//     proofs' `jwk` headers). Signature verification still genuinely
//     runs against those keys, so sealed events stay self-verifying
//     even from quickstart runs — only the binding "the live did.json
//     really lists this key" is waived. Mirrors the noop DNS
//     verifier: real crypto, waived external-world binding. NOT for
//     production.
//
// did:key never reaches this port — its key decodes from the DID
// string with zero I/O.
type DIDResolver interface {
	// Resolve returns the DID document for the given canonical
	// did:web identifier. Implementations return domain errors with
	// the DID_* codes (DID_RESOLUTION_FAILED,
	// DID_DOCUMENT_ID_MISMATCH, DID_REDIRECT_DOMAIN_MISMATCH).
	Resolve(ctx context.Context, did string, hints []KeyHint) (*DIDDocument, error)
}
