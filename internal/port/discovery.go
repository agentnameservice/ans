package port

import (
	"github.com/agentnameservice/ans/internal/domain"
)

// ProfileEmitter is one named DNS discovery family the RA can emit for an
// agent registration. Implementations live under internal/adapter/discovery/
// <vendor>/. Today the bundled set is the ANS family (ANS_DNSAID, ANS_TXT);
// additional families plug in as new vendor packages without touching the
// service or domain layers.
//
// Records is a pure function: no I/O, no context, no error. The service
// layer composes per-profile outputs by walking a ProfileRegistry and
// concatenating each profile's records, deduping by (Name, Type, Value) so
// per-family trust records (e.g. _ans-badge, TLSA) emitted by multiple
// profiles in the same family land once.
type ProfileEmitter interface {
	// ID returns the wire-format identifier (e.g. "ANS_DNSAID", "ANS_TXT").
	// Persisted on agent rows; surfaced on the V2 register schema; used
	// as the registry key.
	ID() domain.DiscoveryProfile

	// Records returns the DNS records this profile needs an operator to
	// publish for reg. Includes both per-profile discovery records and any
	// family-level trust attestation records the profile requires (e.g.
	// _ans-badge for the ANS family, TLSA for any HTTPS-endpoint binding).
	// The service walker dedupes across profiles, so a family's shared
	// records emit once even when multiple sibling profiles request them.
	//
	// A profile that emits a transparency-log-relative trust record (the
	// ANS family's _ans-badge) is configured with the deployment TL URL
	// at construction — see ans.NewTXTProfile / ans.NewDNSAIDProfile — so this
	// stays a pure function of reg with no per-call deployment input.
	Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord
}

// ProfileRegistry is the lookup surface the service uses to compose
// per-profile outputs. Implementations are immutable post-construction so
// reads are safe under concurrent registration / verify-dns load without
// locking. The bundled implementation lives at
// internal/adapter/discovery/registry/registry.go.
type ProfileRegistry interface {
	// Get returns the profile registered under id, or (nil, false) when no
	// such profile is wired. A miss is informational, not an error: the
	// service skips unknown stored profiles (e.g. post-decommission rows)
	// and logs a WARN, rather than failing the registration.
	Get(id domain.DiscoveryProfile) (ProfileEmitter, bool)

	// IDs returns every registered profile's ID in registry-wired
	// insertion order. Order is stable across calls and process restarts
	// for a given wiring — the service walker iterates IDs() and gates
	// each by membership in reg.DiscoveryProfiles, so wiring order
	// determines emission order on the wire (TL canonical bytes).
	IDs() []domain.DiscoveryProfile
}
