package domain

import (
	"strings"
	"time"
)

// AnchorType identifies which family of identity an agent claims.
//
// The three values correspond to the three anchor profiles defined in
// the layered ANS spec under ANS-0 (Identity Anchor):
//
//   - 0.A FQDN: agent identity is a fully-qualified domain name.
//   - 0.B DID: agent identity is a W3C Decentralized Identifier
//     (did:web priority; did:plc, did:key, did:ethr/did:pkh, did:ion
//     supported as profile sub-cases).
//   - 0.C LEI: agent identity is an ISO 17442 Legal Entity Identifier.
//
// The enum is intentionally closed: adding a fourth top-level anchor
// type (e.g., SPIFFE) is an ANS-0 amendment, not a profile addition.
// New DID methods or new LEI registration regimes are profile changes
// and stay under their existing AnchorType. See the proposal at
// docs/proposals/2026-05-16-spec-skeletons/ans-0-identity-anchor.md.
type AnchorType string

const (
	AnchorTypeFQDN AnchorType = "fqdn"
	AnchorTypeDID  AnchorType = "did"
	AnchorTypeLEI  AnchorType = "lei"
)

// IsValid reports whether t is one of the three defined anchor types.
func (t AnchorType) IsValid() bool {
	switch t {
	case AnchorTypeFQDN, AnchorTypeDID, AnchorTypeLEI:
		return true
	}
	return false
}

// IdentityClaim is the typed result of a successful anchor resolution.
//
// Higher-spec code (ANS-1 RegistrationService, ANS-5 VerificationWorker,
// ANS-6 TrustIndex) reads identity through this struct only and never
// branches on the underlying anchor type. The struct shape matches the
// TypeScript signature in docs/spec/ANS_SPEC.md §3.1; profile docs
// under docs/profiles/anchor-0*.md specify how each anchor type is
// resolved.
//
// Field invariants:
//   - AnchorType is non-empty and passes IsValid.
//   - ResolvedID is the canonical normalized form for the anchor type
//     (lowercase no-trailing-dot FQDN, canonical DID URI per W3C DID
//     Core §3.1, 20-char ISO 17442 LEI).
//   - PublicKeyJWK is the JWK-encoded form of the active verification
//     key. The AnchorResolver guarantees the key is currently
//     authoritative for the anchor.
//   - IssuedAt is the time of resolution. Verifiers cache by
//     (anchor input, issuedAt) and re-resolve when the cache exceeds
//     the profile's freshness budget.
//   - ExpiresAt is set when the anchor has an inherent expiration
//     (DNSSEC RRSIG validity end for FQDN, DID document expiry for
//     some DID methods, vLEI credential expiry). Zero-value means no
//     hard expiry; the freshness budget alone bounds cache lifetime.
type IdentityClaim struct {
	AnchorType   AnchorType
	ResolvedID   string
	PublicKeyJWK []byte
	MetadataURL  string
	IssuedAt     time.Time
	ExpiresAt    time.Time // zero-value when the anchor has no hard expiry
}

// IsZero reports whether the claim is unset (zero value).
func (c IdentityClaim) IsZero() bool {
	return c.AnchorType == "" && c.ResolvedID == "" && len(c.PublicKeyJWK) == 0
}

// Validate checks the structural invariants. It does NOT re-validate
// the resolution chain — the AnchorResolver did that work. Validate
// is a defense-in-depth check at API boundaries (e.g., when a claim
// is loaded from storage and passed to a service that did not produce
// it itself).
func (c IdentityClaim) Validate() error {
	if !c.AnchorType.IsValid() {
		return NewValidationError(
			"INVALID_ANCHOR_TYPE",
			"anchorType must be one of fqdn, did, lei",
		)
	}
	if strings.TrimSpace(c.ResolvedID) == "" {
		return NewValidationError(
			"MISSING_RESOLVED_ID",
			"identity claim missing resolvedId",
		)
	}
	if len(c.PublicKeyJWK) == 0 {
		return NewValidationError(
			"MISSING_PUBLIC_KEY",
			"identity claim missing publicKey",
		)
	}
	if c.IssuedAt.IsZero() {
		return NewValidationError(
			"MISSING_ISSUED_AT",
			"identity claim missing issuedAt",
		)
	}
	return nil
}

// FQDN returns the canonical FQDN when the anchor is type fqdn,
// otherwise the empty string. Callers that need the FQDN regardless
// of anchor type should derive it from the registration's AgentHost
// field rather than from the claim.
func (c IdentityClaim) FQDN() string {
	if c.AnchorType == AnchorTypeFQDN {
		return c.ResolvedID
	}
	return ""
}
