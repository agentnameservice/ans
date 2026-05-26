// Package registry holds the immutable composition facade for
// port.DiscoveryStyle implementations. It is the bundled
// port.DiscoveryRegistry: cmd/ans-ra/main.go calls registry.New(...)
// with the styles the binary should serve, and the service consumes the
// returned *Registry through the port interface.
//
// The registry itself is intentionally small (no global state, no
// init-time registration, no plug-in loading). Adding a new style is a
// matter of registering an additional port.DiscoveryStyle in
// cmd/ans-ra/main.go — the contributor walk-through lives in
// docs/contributing-discovery-profiles.md.
package registry

import (
	"fmt"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// Registry composes port.DiscoveryStyle implementations by ID. Immutable
// post-construction: New stores both a lookup map (for O(1) Get) and an
// insertion-order slice (for stable IDs() iteration). Reads are safe for
// concurrent use without locking; there is no Add/Remove API.
type Registry struct {
	styles map[domain.DNSRecordStyle]port.DiscoveryStyle
	order  []domain.DNSRecordStyle
}

// New constructs a Registry from the given styles in argument order.
// Returns an error when any style's ID is invalid (per
// domain.DNSRecordStyle.IsValid) or when two styles share the same ID —
// both are deterministic startup misconfigurations the wiring code in
// cmd/ans-ra/main.go must surface as a fail-loud server-start error,
// rather than degrading silently at the first registration.
//
// Iteration order matches argument order (stable across process restarts
// for a given wiring) so the service walker's emission order on the wire
// is determined here, not by request input.
func New(styles ...port.DiscoveryStyle) (*Registry, error) {
	r := &Registry{
		styles: make(map[domain.DNSRecordStyle]port.DiscoveryStyle, len(styles)),
		order:  make([]domain.DNSRecordStyle, 0, len(styles)),
	}
	for _, s := range styles {
		id := s.ID()
		if !id.IsValid() {
			return nil, fmt.Errorf("registry: style ID %q is not a valid DNSRecordStyle", id)
		}
		if _, dup := r.styles[id]; dup {
			return nil, fmt.Errorf("registry: duplicate style ID %q", id)
		}
		r.styles[id] = s
		r.order = append(r.order, id)
	}
	return r, nil
}

// Get returns the style registered under id, or (nil, false) when no such
// style is wired. Implements port.DiscoveryRegistry.
func (r *Registry) Get(id domain.DNSRecordStyle) (port.DiscoveryStyle, bool) {
	s, ok := r.styles[id]
	return s, ok
}

// IDs returns the registered style IDs in insertion order. The returned
// slice is a fresh copy; callers may mutate it without affecting the
// registry. Implements port.DiscoveryRegistry.
func (r *Registry) IDs() []domain.DNSRecordStyle {
	out := make([]domain.DNSRecordStyle, len(r.order))
	copy(out, r.order)
	return out
}
