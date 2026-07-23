// Package registry holds the immutable composition facade for
// port.ProfileEmitter implementations. It is the bundled
// port.ProfileRegistry: cmd/ans-ra/main.go calls registry.New(...)
// with the profiles the binary should serve, and the service consumes the
// returned *Registry through the port interface.
//
// The registry itself is intentionally small (no global state, no
// init-time registration, no plug-in loading). Adding a new profile is a
// matter of registering an additional port.ProfileEmitter in
// cmd/ans-ra/main.go — the contributor walk-through lives in
// docs/contributing-discovery-profiles.md.
package registry

import (
	"fmt"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// Registry composes port.ProfileEmitter implementations by ID. Immutable
// post-construction: New stores both a lookup map (for O(1) Get) and an
// insertion-order slice (for stable IDs() iteration). Reads are safe for
// concurrent use without locking; there is no Add/Remove API.
type Registry struct {
	profiles map[domain.DiscoveryProfile]port.ProfileEmitter
	order    []domain.DiscoveryProfile
}

// New constructs a Registry from the given profiles in argument order.
// Returns an error when any profile's ID is invalid (per
// domain.DiscoveryProfile.IsValid) or when two profiles share the same ID —
// both are deterministic startup misconfigurations the wiring code in
// cmd/ans-ra/main.go must surface as a fail-loud server-start error,
// rather than degrading silently at the first registration.
//
// Iteration order matches argument order (stable across process restarts
// for a given wiring) so the service walker's emission order on the wire
// is determined here, not by request input.
func New(profiles ...port.ProfileEmitter) (*Registry, error) {
	r := &Registry{
		profiles: make(map[domain.DiscoveryProfile]port.ProfileEmitter, len(profiles)),
		order:    make([]domain.DiscoveryProfile, 0, len(profiles)),
	}
	for _, s := range profiles {
		id := s.ID()
		if !id.IsValid() {
			return nil, fmt.Errorf("registry: profile ID %q is not a valid DiscoveryProfile", id)
		}
		if _, dup := r.profiles[id]; dup {
			return nil, fmt.Errorf("registry: duplicate profile ID %q", id)
		}
		r.profiles[id] = s
		r.order = append(r.order, id)
	}
	return r, nil
}

// Get returns the profile registered under id, or (nil, false) when no such
// profile is wired. Implements port.ProfileRegistry.
func (r *Registry) Get(id domain.DiscoveryProfile) (port.ProfileEmitter, bool) {
	s, ok := r.profiles[id]
	return s, ok
}

// IDs returns the registered profile IDs in insertion order. The returned
// slice is a fresh copy; callers may mutate it without affecting the
// registry. Implements port.ProfileRegistry.
func (r *Registry) IDs() []domain.DiscoveryProfile {
	out := make([]domain.DiscoveryProfile, len(r.order))
	copy(out, r.order)
	return out
}
