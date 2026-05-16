// Package port — anchor resolver contract. Defines the AnchorResolver
// interface higher-level RA code calls into to translate an arbitrary
// anchor input (FQDN, DID URI, LEI string) into a verified
// domain.IdentityClaim. Aligns with the proposed
// docs/spec/ans-0-identity-anchor.md §4 contract.
package port

import (
	"context"

	"github.com/godaddy/ans/internal/domain"
)

// AnchorResolver translates an anchor input string into a verified
// IdentityClaim. Implementations live under
// internal/adapter/anchor/<profile>/ and conform to a profile document
// under docs/profiles/anchor-0*.md.
//
// Resolve performs all four ANS-0 §4.2 verification checks before
// returning: lexical validation, resolution, key authenticity,
// freshness. A failure at any step returns a typed *domain.Error
// whose Code identifies the failure mode (FQDN_BAD_FORMAT,
// FQDN_CERT_CHAIN_INVALID, DID_RESOLUTION_FAILED, LEI_INACTIVE, etc.).
//
// SupportedProfiles enables configuration-driven composition: an RA
// configured to accept FQDN registrations only configures a resolver
// whose SupportedProfiles returns ["0.A-fqdn"]. A multi-anchor RA
// returns the union of profiles its configuration enabled. The set is
// mechanically auditable.
//
// Implementations MAY compose sub-resolvers behind a single
// AnchorResolver facade. The facade dispatches by inspecting the
// input's lexical form (per ANS-0 §4.1):
//
//   - <label>(.<label>)+ matching RFC 1123  → 0.A FQDN
//   - did:<method>:...                      → 0.B DID
//   - 20 alphanumeric chars + ISO 17442 cd  → 0.C LEI
//
// Inputs that match no shape return an INVALID_ANCHOR_FORMAT error
// without invoking any sub-resolver.
type AnchorResolver interface {
	// Resolve validates the input and returns a verified IdentityClaim.
	// Errors are *domain.Error with anchor-profile-specific Codes.
	Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error)

	// SupportedProfiles returns the profile identifiers this resolver
	// can handle. Used by the RA's configuration validator at startup
	// to confirm the resolver supports every profile the deployment's
	// config admits. Examples: ["0.A-fqdn"], ["0.B-did:web",
	// "0.B-did:plc"], ["0.A-fqdn", "0.B-did:web"].
	SupportedProfiles() []string
}
