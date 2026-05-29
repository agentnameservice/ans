package port

import (
	"github.com/godaddy/ans/internal/domain"
)

// DiscoveryStyle is one named DNS discovery family the RA can emit for an
// agent registration. Implementations live under internal/adapter/discovery/
// <vendor>/. Today the bundled set is the ANS family (ANS_SVCB, ANS_TXT);
// additional families plug in as new vendor packages without touching the
// service or domain layers.
//
// Records is a pure function: no I/O, no context, no error. The service
// layer composes per-style outputs by walking a DiscoveryRegistry and
// concatenating each style's records, deduping by (Name, Type, Value) so
// per-family trust records (e.g. _ans-badge, TLSA) emitted by multiple
// styles in the same family land once.
type DiscoveryStyle interface {
	// ID returns the wire-format identifier (e.g. "ANS_SVCB", "ANS_TXT").
	// Persisted on agent rows; surfaced on the V2 register schema; used
	// as the registry key.
	ID() domain.DNSRecordStyle

	// Records returns the DNS records this style needs an operator to
	// publish for reg. Includes both per-style discovery records and any
	// family-level trust attestation records the style requires (e.g.
	// _ans-badge for the ANS family, TLSA for any HTTPS-endpoint binding).
	// The service walker dedupes across styles, so a family's shared
	// records emit once even when multiple sibling styles request them.
	//
	// A style that emits a transparency-log-relative trust record (the
	// ANS family's _ans-badge) is configured with the deployment TL URL
	// at construction — see ans.NewTXTStyle / ans.NewSVCBStyle — so this
	// stays a pure function of reg with no per-call deployment input.
	Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord
}

// DiscoveryRegistry is the lookup surface the service uses to compose
// per-style outputs. Implementations are immutable post-construction so
// reads are safe under concurrent registration / verify-dns load without
// locking. The bundled implementation lives at
// internal/adapter/discovery/registry/registry.go.
type DiscoveryRegistry interface {
	// Get returns the style registered under id, or (nil, false) when no
	// such style is wired. A miss is informational, not an error: the
	// service skips unknown stored styles (e.g. post-decommission rows)
	// and logs a WARN, rather than failing the registration.
	Get(id domain.DNSRecordStyle) (DiscoveryStyle, bool)

	// IDs returns every registered style's ID in registry-wired
	// insertion order. Order is stable across calls and process restarts
	// for a given wiring — the service walker iterates IDs() and gates
	// each by membership in reg.DNSRecordStyles, so wiring order
	// determines emission order on the wire (TL canonical bytes).
	IDs() []domain.DNSRecordStyle
}
