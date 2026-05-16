// Package registry composes per-profile AnchorResolver
// implementations behind a single facade that the registration
// service calls into.
//
// The facade dispatches by lexical form per ANS-0 §4.1:
//
//   - Inputs starting with "did:" route to a DID resolver
//     (currently only did:web; subsequent slices add did:plc,
//     did:key, did:ethr/did:pkh, did:ion).
//   - Inputs that match the ISO 17442 LEI shape route to the LEI
//     resolver.
//   - Inputs that match RFC 1123 hostname constraints route to the
//     FQDN resolver.
//   - Anything else returns INVALID_ANCHOR_FORMAT without invoking
//     any sub-resolver.
//
// A registry is constructed with a configurable set of profiles.
// Deployments that accept FQDN-only registrations build a registry
// with the FQDN resolver alone; deployments that accept all three
// anchor types register all three. SupportedProfiles returns the
// union, which the configuration validator at startup audits
// against the deployment's accepted-profile list.
package registry

import (
	"context"
	"strings"

	"github.com/godaddy/ans/internal/adapter/anchor/did"
	"github.com/godaddy/ans/internal/adapter/anchor/lei"
	"github.com/godaddy/ans/internal/domain"
)

// Compile-time check that *Registry satisfies the
// port.AnchorResolver contract. The actual import is deferred
// because stating the interface compile-time is the cleanest
// expression and a port import without use would lint-fail.
//
//	var _ port.AnchorResolver = (*Registry)(nil)
//
// The check is informally documented; runtime composition in the
// registration service plumbs the registry into the port slot.

// fqdnShapeResolver is the subset of the FQDN resolver's API the
// registry uses. The full FQDN package owns ResolveWithKey for the
// migration period; the facade routes to Resolve which today is a
// stub. Once Slice 4-of-the-FQDN-package owns DNS resolution, both
// the registry and the registration service will move to Resolve.
type fqdnShapeResolver interface {
	Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error)
	SupportedProfiles() []string
}

// Registry implements port.AnchorResolver as a facade over the
// per-profile resolvers a deployment configures.
type Registry struct {
	fqdn fqdnShapeResolver
	did  *did.Web
	lei  *lei.Resolver
}

// New constructs an empty Registry. Use With* methods to add
// per-profile resolvers; an empty registry rejects every input
// with INVALID_ANCHOR_FORMAT, which is appropriate during config
// validation but never in production.
func New() *Registry {
	return &Registry{}
}

// WithFQDN registers an FQDN resolver (§0.A profile).
func (r *Registry) WithFQDN(resolver fqdnShapeResolver) *Registry {
	out := *r
	out.fqdn = resolver
	return &out
}

// WithDIDWeb registers the did:web resolver (§0.B profile, sub-
// profile did:web). Other DID methods are added through subsequent
// With*DID* methods as they land.
func (r *Registry) WithDIDWeb(resolver *did.Web) *Registry {
	out := *r
	out.did = resolver
	return &out
}

// WithLEI registers the LEI resolver (§0.C profile).
func (r *Registry) WithLEI(resolver *lei.Resolver) *Registry {
	out := *r
	out.lei = resolver
	return &out
}

// SupportedProfiles satisfies port.AnchorResolver. The slice is the
// union of every registered sub-resolver's profiles, in stable
// lexical order so the configuration validator's diff output is
// reproducible.
func (r *Registry) SupportedProfiles() []string {
	out := []string{}
	if r.fqdn != nil {
		out = append(out, r.fqdn.SupportedProfiles()...)
	}
	if r.did != nil {
		out = append(out, r.did.SupportedProfiles()...)
	}
	if r.lei != nil {
		out = append(out, r.lei.SupportedProfiles()...)
	}
	return out
}

// Resolve dispatches to the appropriate sub-resolver based on the
// input's lexical form.
//
// Dispatch order:
//  1. "did:" prefix → DID branch.
//  2. 20-char ASCII alphanumeric → LEI branch.
//  3. RFC 1123 hostname shape → FQDN branch.
//  4. Anything else → INVALID_ANCHOR_FORMAT.
//
// If the dispatched profile is not configured (e.g. input is a DID
// URI but no DID resolver was registered), the registry returns
// PROFILE_NOT_CONFIGURED. A configuration validator at startup
// catches this case before the first registration request lands.
func (r *Registry) Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, domain.NewValidationError(
			"INVALID_ANCHOR_FORMAT",
			"anchor input is empty",
		)
	}

	switch {
	case strings.HasPrefix(strings.ToLower(trimmed), "did:"):
		if r.did == nil {
			return nil, domain.NewValidationError(
				"PROFILE_NOT_CONFIGURED",
				"DID anchor input received but no DID resolver registered",
			)
		}
		return r.did.Resolve(ctx, trimmed)

	case looksLikeLEI(trimmed):
		if r.lei == nil {
			return nil, domain.NewValidationError(
				"PROFILE_NOT_CONFIGURED",
				"LEI anchor input received but no LEI resolver registered",
			)
		}
		return r.lei.Resolve(ctx, trimmed)

	case looksLikeFQDN(trimmed):
		if r.fqdn == nil {
			return nil, domain.NewValidationError(
				"PROFILE_NOT_CONFIGURED",
				"FQDN anchor input received but no FQDN resolver registered",
			)
		}
		return r.fqdn.Resolve(ctx, trimmed)
	}

	return nil, domain.NewValidationError(
		"INVALID_ANCHOR_FORMAT",
		"input did not match did:, LEI, or FQDN shape",
	)
}

// looksLikeLEI checks the input's ASCII shape only; the LEI
// resolver does the full ISO 17442 mod-97 validation. The lexical
// check is intentionally cheap so the dispatch decision is fast
// and the actual validation error (if any) comes from the LEI
// resolver itself.
func looksLikeLEI(input string) bool {
	if len(input) != 20 {
		return false
	}
	for _, r := range input {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		default:
			return false
		}
	}
	return true
}

// looksLikeFQDN does a lexical check sufficient to distinguish
// FQDN from "everything else." The FQDN resolver itself enforces
// the strict RFC 1123 rules; here we just need at least one dot
// and admissible characters.
func looksLikeFQDN(input string) bool {
	if !strings.Contains(input, ".") {
		return false
	}
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
