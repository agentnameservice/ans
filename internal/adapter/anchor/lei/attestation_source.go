// attestation_source.go separates the entity-verification responsibility
// (handled by GLEIFClient) from the attestation-key responsibility
// (the entity's published verification key the agent uses to sign
// registration events).
//
// The GLEIF Public API does not carry an attestation key in the
// Level 1 record. Two paths populate the key:
//
//   - vLEI Option A: a self-attestation issued through GLEIF's vLEI
//     infrastructure, fetched via that infrastructure's API.
//   - vLEI Option B: a custom field at the entity's Local Operating
//     Unit (LOU), retrieved through the LOU's API.
//
// Both paths are deployment choices, not protocol-level concerns.
// The Resolver composes a GLEIFClient (entity verification) with an
// AttestationJWKSource (key retrieval); the two surfaces stay
// independent so a deployment can use the basic GLEIF Level 1 API
// for verification and a separate pluggable source for the key.
package lei

import (
	"context"
	"sync"
)

// AttestationJWKSource returns the entity's published verification
// key as a JWK byte sequence (RFC 7517).
//
// Implementations MUST be safe for concurrent use. The Resolver may
// call Lookup concurrently from multiple verification cycles.
type AttestationJWKSource interface {
	// Lookup returns the JWK bytes for the given (canonical, uppercase)
	// LEI. Returns nil with no error when the source has no key for
	// the LEI; the caller decides whether absence is a failure.
	Lookup(ctx context.Context, lei string) ([]byte, error)
}

// StaticAttestationSource is an in-memory map from LEI to JWK bytes.
// Useful for testbeds, integration tests, and deployments that
// preconfigure entity keys out-of-band (e.g., from a sealed config
// file or a secret store).
//
// A vLEI-aware source replaces this in production deployments that
// resolve keys through GLEIF's vLEI infrastructure.
type StaticAttestationSource struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewStaticAttestationSource returns an empty static source.
// Populate it with Set before passing it to Resolver.WithAttestationSource.
func NewStaticAttestationSource() *StaticAttestationSource {
	return &StaticAttestationSource{
		keys: make(map[string][]byte),
	}
}

// Set registers a JWK for the given LEI. The LEI is canonicalized
// to uppercase before storage so callers may pass either form.
func (s *StaticAttestationSource) Set(lei string, jwk []byte) {
	canonical, err := Canonicalize(lei)
	if err != nil {
		// Stored as the input form; Lookup will not match. Caller
		// bug surfaces at lookup time rather than here. Keeping Set
		// non-erroring lets callers wire up a source from config
		// without a separate validation step.
		canonical = lei
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(jwk))
	copy(cp, jwk)
	s.keys[canonical] = cp
}

// Lookup implements AttestationJWKSource. Returns a defensive copy
// so callers cannot mutate the stored bytes.
func (s *StaticAttestationSource) Lookup(_ context.Context, lei string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.keys[lei]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(stored))
	copy(cp, stored)
	return cp, nil
}
