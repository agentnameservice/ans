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
	want := []string{"ANS_SVCB", "ANS_TXT"}
	assert.Equal(t, want, got)
}

// TestDefaultDiscoveryProfiles pins the default set applied when a V2
// register request omits discoveryProfiles. {ANS_SVCB} per §4.4.2.
func TestDefaultDiscoveryProfiles(t *testing.T) {
	got := DefaultDiscoveryProfiles()
	want := []DiscoveryProfile{DiscoveryProfileANSSVCB}
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
		{name: "ans_svcb_is_valid", s: DiscoveryProfileANSSVCB, want: true},
		{name: "ans_txt_is_valid", s: DiscoveryProfileANSTXT, want: true},
		{name: "empty_is_invalid", s: DiscoveryProfile(""), want: false},
		{name: "unknown_is_invalid", s: DiscoveryProfile("UNKNOWN_FAMILY"), want: false},
		{name: "lowercase_is_invalid", s: DiscoveryProfile("ans_svcb"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.IsValid())
		})
	}
}
