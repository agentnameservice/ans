// Package fqdn implements the ANS-0 §0.A FQDN anchor profile.
//
// FQDN is the dominant anchor type for ANS-registered agents. This
// resolver lifts the FQDN-specific lexical and shape validation that
// previously lived inline in the registration service into a typed
// AnchorResolver. The resolver returns an IdentityClaim whose
// PublicKeyJWK is supplied by the caller (the registration flow has
// already validated the certificate chain at this point); the
// resolver's job is to canonicalize the FQDN, sanity-check it
// against RFC 1123, and stamp the claim's metadata.
//
// Plan G Slice 1 keeps the resolver behavior-preserving: existing
// FQDN registrations land identical IdentityClaim values regardless
// of whether the resolver is on the hot path or bypassed. Subsequent
// slices add the optional DNSid pre-step (anchor-0a-fqdn.md §3.4)
// and the ACME challenge resolution that is currently inline in
// internal/ra/service/lifecycle.go.
package fqdn

import (
	"context"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ProfileID is the canonical identifier for this resolver in the
// AnchorResolverRegistry advertised through SupportedProfiles().
// Matches docs/profiles/anchor-0a-fqdn.md.
const ProfileID = "0.A-fqdn"

// Resolver implements port.AnchorResolver for FQDN anchors.
//
// The resolver is stateless; it carries no DNS client and no cert
// validator of its own. Higher-level service code performs the
// certificate chain validation and DNSSEC checks (the existing
// registration flow does this through the certificate-validator port);
// this resolver shapes the validated material into an IdentityClaim.
//
// A future Slice will pull DNS resolution and DNSSEC validation into
// this package so the resolver becomes the canonical home for FQDN
// resolution rather than a thin shape-converter. For now, keep the
// surface minimal so the abstraction is testable in isolation.
type Resolver struct {
	clock func() time.Time
}

// New constructs a Resolver using time.Now as the clock.
func New() *Resolver {
	return &Resolver{clock: time.Now}
}

// WithClock returns a copy of the resolver with the given clock
// function. Tests use this to make IssuedAt deterministic.
func (r *Resolver) WithClock(clock func() time.Time) *Resolver {
	return &Resolver{clock: clock}
}

// SupportedProfiles satisfies port.AnchorResolver.
func (r *Resolver) SupportedProfiles() []string {
	return []string{ProfileID}
}

// Resolve validates an FQDN input and returns an IdentityClaim.
//
// At this slice, Resolve performs only the lexical step (ANS-0 §4.2
// step 1) and stamps IssuedAt; the resolution + key authenticity +
// freshness steps remain in the existing registration service code
// path that this resolver will absorb in Slice 4. Calling Resolve
// without an explicit publicKey input would force the resolver to
// fetch the cert chain itself, which couples the package to the
// validator port; the explicit-key shape keeps the resolver narrow
// for now.
//
// Callers building a claim from an already-validated certificate
// should use ResolveWithKey, which is the primary entry point during
// the abstraction migration. Resolve is provided for future use when
// the resolver owns the full chain; today it returns a
// not-implemented error to flag the migration boundary.
func (r *Resolver) Resolve(_ context.Context, _ string) (*domain.IdentityClaim, error) {
	return nil, domain.NewInternalError(
		"FQDN_RESOLVE_NOT_IMPLEMENTED",
		"FQDN resolver is currently shape-only; use ResolveWithKey from "+
			"the registration service until Slice 4 absorbs DNS resolution",
		nil,
	)
}

// ResolveWithKey is the slice-1 entry point used by the registration
// service. The caller (registration service or renewal service)
// validates the certificate chain through the existing certificate-
// validator port and hands the public key in JWK form. The resolver
// canonicalizes the FQDN, validates it lexically, and shapes the
// IdentityClaim.
//
// Returned errors are *domain.Error with codes:
//
//   - FQDN_BAD_FORMAT      input is empty, too long, or fails RFC 1123
//   - FQDN_LABEL_BAD       a label is empty, too long, or non-LDH
//
// metadataURL is optional and typically points at the agent's Trust
// Card location (https://<fqdn>/.well-known/ans/trust-card.json).
// Empty metadataURL produces a claim with an empty MetadataURL field,
// which higher-spec code treats as "fall back to the default
// well-known path."
func (r *Resolver) ResolveWithKey(input string, publicKeyJWK []byte, metadataURL string) (*domain.IdentityClaim, error) {
	canonical, err := canonicalize(input)
	if err != nil {
		return nil, err
	}
	if len(publicKeyJWK) == 0 {
		return nil, domain.NewValidationError(
			"MISSING_PUBLIC_KEY",
			"public key is required to construct an FQDN identity claim",
		)
	}
	return &domain.IdentityClaim{
		AnchorType:   domain.AnchorTypeFQDN,
		ResolvedID:   canonical,
		PublicKeyJWK: publicKeyJWK,
		MetadataURL:  metadataURL,
		IssuedAt:     r.clock().UTC(),
	}, nil
}

// canonicalize lowercases the input, strips any trailing dot, and
// validates the result against RFC 1123 hostname constraints.
func canonicalize(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", domain.NewValidationError(
			"FQDN_BAD_FORMAT",
			"FQDN cannot be empty",
		)
	}
	// Strip a single trailing dot (root label form). Multiple
	// trailing dots are malformed.
	canonical := strings.TrimSuffix(strings.ToLower(trimmed), ".")
	// Total length cap per RFC 1035 §3.1 / RFC 1123 §2.1: 253 chars.
	if len(canonical) > 253 {
		return "", domain.NewValidationError(
			"FQDN_BAD_FORMAT",
			"FQDN exceeds 253-character limit",
		)
	}
	if strings.ContainsAny(canonical, " \t\n\r") {
		return "", domain.NewValidationError(
			"FQDN_BAD_FORMAT",
			"FQDN must not contain whitespace",
		)
	}
	if !strings.Contains(canonical, ".") {
		return "", domain.NewValidationError(
			"FQDN_BAD_FORMAT",
			"FQDN must contain at least one dot (one or more labels)",
		)
	}
	for _, label := range strings.Split(canonical, ".") {
		if err := validateLabel(label); err != nil {
			return "", err
		}
	}
	return canonical, nil
}

// validateLabel applies RFC 1123 §2.1 label rules. A label must be
// 1-63 LDH characters and must not start or end with a hyphen.
// Underscores are intentionally rejected: ANS-3 reserves underscore-
// prefixed names for the registry-controlled records and the agent's
// FQDN must not collide with that scheme.
func validateLabel(label string) error {
	if label == "" {
		return domain.NewValidationError(
			"FQDN_LABEL_BAD",
			"FQDN label cannot be empty (consecutive dots)",
		)
	}
	if len(label) > 63 {
		return domain.NewValidationError(
			"FQDN_LABEL_BAD",
			"FQDN label exceeds 63 characters",
		)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return domain.NewValidationError(
			"FQDN_LABEL_BAD",
			"FQDN label must not start or end with a hyphen",
		)
	}
	for _, c := range label {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return domain.NewValidationError(
				"FQDN_LABEL_BAD",
				"FQDN label contains invalid character: "+string(c),
			)
		}
	}
	return nil
}
