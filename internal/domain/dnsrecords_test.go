package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidDiscoveryProfiles pins the canonical valid set of
// DiscoveryProfile values returned by the helper used in the V2
// INVALID_DISCOVERY_PROFILE error message and (eventually) by spec
// generation tooling. Order and contents are stable so an external
// client's error-message fixtures can match.
func TestValidDiscoveryProfiles(t *testing.T) {
	got := ValidDiscoveryProfiles()
	want := []string{"ANS_DNSAID", "ANS_TXT"}
	assert.Equal(t, want, got)
}

// TestDefaultDiscoveryProfiles pins the default set applied when a V2
// register request omits discoveryProfiles. Pinned to the stable
// {ANS_TXT} family while ANS_DNSAID is brought to conformance.
func TestDefaultDiscoveryProfiles(t *testing.T) {
	got := DefaultDiscoveryProfiles()
	want := []DiscoveryProfile{DiscoveryProfileANSTXT}
	assert.Equal(t, want, got)
}

// TestDiscoveryProfile_IsValid covers the typed-enum membership predicate
// applyDiscoveryProfiles and the registry-coherence check both rely on.
func TestDiscoveryProfile_IsValid(t *testing.T) {
	tests := []struct {
		name string
		s    DiscoveryProfile
		want bool
	}{
		{name: "ans_dnsaid_is_valid", s: DiscoveryProfileANSDNSAID, want: true},
		{name: "ans_txt_is_valid", s: DiscoveryProfileANSTXT, want: true},
		{name: "empty_is_invalid", s: DiscoveryProfile(""), want: false},
		{name: "unknown_is_invalid", s: DiscoveryProfile("UNKNOWN_FAMILY"), want: false},
		{name: "lowercase_is_invalid", s: DiscoveryProfile("ans_dnsaid"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.IsValid())
		})
	}
}
