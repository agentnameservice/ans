package service

import (
	"github.com/agentnameservice/ans/internal/adapter/discovery/ans"
	"github.com/agentnameservice/ans/internal/adapter/discovery/registry"
	"github.com/agentnameservice/ans/internal/port"
)

// NewDefaultProfileRegistry returns a registry pre-wired with the
// bundled ANS-family profiles (TXTProfile, DNSAIDProfile) in the canonical
// emission order — TXT first, SVCB second — that the V2 TL canonical
// bytes for the union case were established at. cmd/ans-ra/main.go
// uses it for production wiring; tests across the RA layer use it
// for fixture construction so all paths exercise the same emission
// shape.
//
// Iteration order is the load-bearing part: the service walker
// emits records in registry insertion order, and TL leaves carry
// `dnsRecordsProvisioned[]` byte-for-byte from that ordering. Any
// future production deployment that swaps in a different profile set
// MUST construct the registry with TXTProfile and DNSAIDProfile in this
// same relative order to preserve canonical-bytes parity for
// existing agents.
//
// Errors only when registry.New rejects the wiring (duplicate IDs,
// invalid IDs) — the bundled set passes both checks deterministically,
// but the error return preserves callers' ability to fail loudly on
// startup misconfig per the no-panic-in-request-paths rule.
//
// tlPublicBaseURL is the externally-reachable Transparency Log URL the
// ANS profiles stamp into the family `_ans-badge` record's url= (see
// ans.NewTXTProfile / ans.NewDNSAIDProfile). Empty — tests, or a deployment
// without a public TL URL — falls the badge back to the agent's own
// endpoint URL.
func NewDefaultProfileRegistry(tlPublicBaseURL string) (port.ProfileRegistry, error) {
	return registry.New(
		ans.NewTXTProfile(tlPublicBaseURL),
		ans.NewDNSAIDProfile(tlPublicBaseURL),
	)
}
