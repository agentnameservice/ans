// Package lei implements the ANS-0 §0.C LEI anchor profile per
// docs/profiles/anchor-0c-lei.md.
//
// This package handles the lexical and check-digit validation that
// is portable across deployments (no GLEIF API access required) and
// stubs the actual GLEIF resolution behind a Resolver type. The
// stubbed Resolve method returns LEI_GLEIF_NOT_CONFIGURED until a
// caller injects a GLEIF client through WithClient. That keeps the
// package useful for testbeds and unit tests without forcing every
// downstream environment to acquire GLEIF API credentials.
//
// Slice 3 ships the format validation, mod-97 check-digit
// verification, canonical normalization, and the SupportedProfiles
// surface. The HTTPS GET pipeline against api.gleif.org and the
// vLEI self-attestation Option A path land in a follow-up slice
// once a GLEIF testbed is wired into CI.
package lei

import (
	"context"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ProfileID is the canonical identifier for this resolver in the
// AnchorResolverRegistry advertised through SupportedProfiles().
// Matches docs/profiles/anchor-0c-lei.md.
const ProfileID = "0.C-lei"

// freshnessBudget bounds the cache lifetime of a resolved
// IdentityClaim. 7 days matches the recommendation in
// docs/profiles/anchor-0c-lei.md §3.5; verifiers in regulated
// verticals MAY shorten per local policy.
const freshnessBudget = 7 * 24 * time.Hour

// GLEIFClient abstracts the GLEIF API surface the resolver needs.
// Implementations live outside this package so the resolver does
// not link the GLEIF HTTP transport at compile time. The signature
// is intentionally minimal; richer fields (parent/child
// relationships, registration history) live behind a richer client
// the resolver can compose with later.
type GLEIFClient interface {
	// LookupRecord returns the GLEIF Level 1 / Level 2 record for
	// the given LEI. The record carries the entity's status, name,
	// jurisdiction, and (under the vLEI Option A path) the entity's
	// ANS attestation public key as a self-attestation.
	LookupRecord(ctx context.Context, lei string) (*GLEIFRecord, error)
}

// GLEIFRecord is the subset of the GLEIF response the resolver
// needs to construct an IdentityClaim. Adding fields here is safe;
// the JSON decode in a future client implementation ignores anything
// not declared.
type GLEIFRecord struct {
	LEI            string
	EntityName     string
	EntityStatus   string // "ACTIVE", "INACTIVE", "LAPSED", "RETIRED", "MERGED"
	Jurisdiction   string
	AttestationJWK []byte // entity's ANS attestation key in JWK form
	UpdatedAt      time.Time
}

// Resolver implements port.AnchorResolver for LEI anchors. The
// stub form (no client injected) handles format-only resolution and
// surfaces a clear LEI_GLEIF_NOT_CONFIGURED error on Resolve.
// Production deployments inject a GLEIFClient via WithClient.
type Resolver struct {
	client GLEIFClient
	clock  func() time.Time
}

// New constructs a Resolver with no GLEIF client. Format
// validation works; full resolution returns
// LEI_GLEIF_NOT_CONFIGURED until WithClient is used.
func New() *Resolver {
	return &Resolver{clock: time.Now}
}

// WithClient injects a GLEIF client and returns a copy of the
// resolver. The client owns the GLEIF root certificate pinning,
// rate limiting, and any LOU mirror selection per
// anchor-0c-lei.md §3.3.
func (r *Resolver) WithClient(c GLEIFClient) *Resolver {
	return &Resolver{client: c, clock: r.clock}
}

// WithClock returns a copy of the resolver with a deterministic
// clock. Tests use this so IssuedAt is reproducible.
func (r *Resolver) WithClock(clock func() time.Time) *Resolver {
	return &Resolver{client: r.client, clock: clock}
}

// SupportedProfiles satisfies port.AnchorResolver.
func (r *Resolver) SupportedProfiles() []string {
	return []string{ProfileID}
}

// Resolve implements port.AnchorResolver for LEI anchors.
//
// Pipeline:
//  1. Lexical validation: 20 ASCII alphanumeric characters.
//  2. Check-digit validation: ISO 17442 mod-97 == 1.
//  3. Canonicalize to uppercase.
//  4. If no GLEIF client is configured, return
//     LEI_GLEIF_NOT_CONFIGURED. This is the slice-3 boundary; a
//     follow-up slice wires the production client.
//  5. Fetch the GLEIF record via the configured client.
//  6. Validate the entity status is ACTIVE; reject INACTIVE /
//     LAPSED / RETIRED / MERGED with LEI_INACTIVE.
//  7. Construct the IdentityClaim with the entity's attestation
//     JWK. ExpiresAt is now + 7 days (the freshness budget).
func (r *Resolver) Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error) {
	canonical, err := Canonicalize(input)
	if err != nil {
		return nil, err
	}
	if r.client == nil {
		return nil, domain.NewInternalError(
			"LEI_GLEIF_NOT_CONFIGURED",
			"LEI resolver has no GLEIF client configured; format validated but "+
				"full resolution requires WithClient injection",
			nil,
		)
	}
	record, err := r.client.LookupRecord(ctx, canonical)
	if err != nil {
		return nil, domain.NewValidationError(
			"LEI_RESOLUTION_FAILED",
			"GLEIF lookup failed: "+err.Error(),
		)
	}
	if record == nil {
		return nil, domain.NewValidationError(
			"LEI_UNKNOWN",
			"GLEIF returned no record for "+canonical,
		)
	}
	if !strings.EqualFold(record.EntityStatus, "ACTIVE") {
		return nil, domain.NewValidationError(
			"LEI_INACTIVE",
			"entity status is "+record.EntityStatus+"; only ACTIVE LEIs admitted",
		)
	}
	if len(record.AttestationJWK) == 0 {
		return nil, domain.NewValidationError(
			"LEI_NO_ATTESTATION_KEY",
			"GLEIF record has no ANS attestation key registered for "+canonical,
		)
	}
	now := r.clock().UTC()
	return &domain.IdentityClaim{
		AnchorType:   domain.AnchorTypeLEI,
		ResolvedID:   canonical,
		PublicKeyJWK: record.AttestationJWK,
		IssuedAt:     now,
		ExpiresAt:    now.Add(freshnessBudget),
	}, nil
}

// Canonicalize validates the input as an ISO 17442 LEI and returns
// the canonical uppercase form.
//
// The check-digit rule is the ISO 7064 MOD 97-10 form: rewrite the
// LEI's first 18 characters as a numeric string (A=10, B=11, ...,
// Z=35), append the two-digit check field, then compute mod 97.
// The result MUST be 1.
func Canonicalize(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) != 20 {
		return "", domain.NewValidationError(
			"LEI_BAD_FORMAT",
			"LEI must be exactly 20 characters",
		)
	}
	upper := strings.ToUpper(trimmed)
	for _, r := range upper {
		if !isASCIIAlphanumeric(r) {
			return "", domain.NewValidationError(
				"LEI_BAD_FORMAT",
				"LEI contains non-alphanumeric character",
			)
		}
	}
	if !validMod97(upper) {
		return "", domain.NewValidationError(
			"LEI_BAD_CHECK_DIGITS",
			"LEI fails ISO 17442 mod-97 check",
		)
	}
	return upper, nil
}

func isASCIIAlphanumeric(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z')
}

// validMod97 implements the ISO 7064 MOD 97-10 check used by
// ISO 17442 §5.1. Letters expand to two digits (A=10..Z=35); the
// 20-character string then forms a large integer whose modulus 97
// MUST be 1.
//
// The arithmetic uses incremental modulus to avoid big.Int: at each
// step, multiply the running value by 10 (for digits) or 100 (for
// letters expanded to two digits), add the new digit(s), then take
// mod 97. The check-digit positions (chars 5-6) are part of the
// 20-character string so we never need to extract them separately.
func validMod97(lei string) bool {
	const modulus = 97
	r := 0
	for _, c := range lei {
		switch {
		case c >= '0' && c <= '9':
			r = (r*10 + int(c-'0')) % modulus
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10 // A=10, ..., Z=35
			r = (r*100 + v) % modulus
		default:
			return false
		}
	}
	return r == 1
}
