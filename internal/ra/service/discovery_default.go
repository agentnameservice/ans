package service

import (
	"github.com/godaddy/ans/internal/adapter/discovery/ans"
	"github.com/godaddy/ans/internal/adapter/discovery/registry"
	"github.com/godaddy/ans/internal/port"
)

// NewDefaultDiscoveryRegistry returns a registry pre-wired with the
// bundled ANS-family styles (TXTStyle, SVCBStyle) in the canonical
// emission order — TXT first, SVCB second — that the V2 TL canonical
// bytes for the union case were established at. cmd/ans-ra/main.go
// uses it for production wiring; tests across the RA layer use it
// for fixture construction so all paths exercise the same emission
// shape.
//
// Iteration order is the load-bearing part: the service walker
// emits records in registry insertion order, and TL leaves carry
// `dnsRecordsProvisioned[]` byte-for-byte from that ordering. Any
// future production deployment that swaps in a different style set
// MUST construct the registry with TXTStyle and SVCBStyle in this
// same relative order to preserve canonical-bytes parity for
// existing agents.
//
// Errors only when registry.New rejects the wiring (duplicate IDs,
// invalid IDs) — the bundled set passes both checks deterministically,
// but the error return preserves callers' ability to fail loudly on
// startup misconfig per the no-panic-in-request-paths rule.
//
// tlPublicBaseURL is the externally-reachable Transparency Log URL the
// ANS styles stamp into the family `_ans-badge` record's url= (see
// ans.NewTXTStyle / ans.NewSVCBStyle). Empty — tests, or a deployment
// without a public TL URL — falls the badge back to the agent's own
// endpoint URL.
func NewDefaultDiscoveryRegistry(tlPublicBaseURL string) (port.DiscoveryRegistry, error) {
	return registry.New(
		ans.NewTXTStyle(tlPublicBaseURL),
		ans.NewSVCBStyle(tlPublicBaseURL),
	)
}
