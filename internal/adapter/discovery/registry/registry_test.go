package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// fakeProfile is a minimal port.ProfileEmitter test double. ID() is the
// only behavior the registry inspects; Records() returns nil so the
// fake stays cheap to instantiate in tables.
type fakeProfile struct{ id domain.DiscoveryProfile }

func (f fakeProfile) ID() domain.DiscoveryProfile { return f.id }
func (f fakeProfile) Records(*domain.AgentRegistration) []domain.ExpectedDNSRecord {
	return nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		profiles  []port.ProfileEmitter
		wantErr   string // substring; empty means success expected
		wantOrder []domain.DiscoveryProfile
	}{
		{
			name:      "empty_registry_constructs",
			profiles:  nil,
			wantOrder: []domain.DiscoveryProfile{},
		},
		{
			name:      "single_valid_profile",
			profiles:  []port.ProfileEmitter{fakeProfile{id: domain.DiscoveryProfileANSDNSAID}},
			wantOrder: []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
		},
		{
			name: "two_valid_profiles_preserve_argument_order",
			profiles: []port.ProfileEmitter{
				fakeProfile{id: domain.DiscoveryProfileANSTXT},
				fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
			},
			wantOrder: []domain.DiscoveryProfile{
				domain.DiscoveryProfileANSTXT,
				domain.DiscoveryProfileANSDNSAID,
			},
		},
		{
			name: "duplicate_id_rejected",
			profiles: []port.ProfileEmitter{
				fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
				fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
			},
			wantErr: "duplicate profile ID",
		},
		{
			name: "invalid_id_rejected",
			profiles: []port.ProfileEmitter{
				fakeProfile{id: domain.DiscoveryProfile("NOT_A_STYLE")},
			},
			wantErr: "is not a valid DiscoveryProfile",
		},
		{
			name: "invalid_id_rejected_after_valid_one",
			profiles: []port.ProfileEmitter{
				fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
				fakeProfile{id: domain.DiscoveryProfile("")},
			},
			wantErr: "is not a valid DiscoveryProfile",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.profiles...)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, r)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, r)
			assert.Equal(t, tc.wantOrder, r.IDs())
		})
	}
}

func TestGet(t *testing.T) {
	svcb := fakeProfile{id: domain.DiscoveryProfileANSDNSAID}
	txt := fakeProfile{id: domain.DiscoveryProfileANSTXT}
	r, err := New(svcb, txt)
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      domain.DiscoveryProfile
		wantHit bool
		wantID  domain.DiscoveryProfile
	}{
		{name: "hit_svcb", id: domain.DiscoveryProfileANSDNSAID, wantHit: true, wantID: domain.DiscoveryProfileANSDNSAID},
		{name: "hit_txt", id: domain.DiscoveryProfileANSTXT, wantHit: true, wantID: domain.DiscoveryProfileANSTXT},
		{name: "miss_unknown_style", id: domain.DiscoveryProfile("UNKNOWN_FAMILY"), wantHit: false},
		{name: "miss_empty_id", id: domain.DiscoveryProfile(""), wantHit: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Get(tc.id)
			assert.Equal(t, tc.wantHit, ok)
			if tc.wantHit {
				require.NotNil(t, got)
				assert.Equal(t, tc.wantID, got.ID())
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

// TestIDs_ReturnsCopy pins that the slice IDs() returns is a fresh copy —
// callers mutating it must not affect the registry's internal order, so
// concurrent readers can safely iterate without coordination.
func TestIDs_ReturnsCopy(t *testing.T) {
	r, err := New(
		fakeProfile{id: domain.DiscoveryProfileANSTXT},
		fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
	)
	require.NoError(t, err)

	first := r.IDs()
	first[0] = domain.DiscoveryProfile("MUTATED")

	second := r.IDs()
	assert.Equal(t, []domain.DiscoveryProfile{
		domain.DiscoveryProfileANSTXT,
		domain.DiscoveryProfileANSDNSAID,
	}, second, "mutating one IDs() result must not affect a subsequent call")
}

// TestIDs_StableAcrossCalls pins that two consecutive IDs() calls return
// the same insertion order. Map iteration is non-deterministic in Go;
// the registry must materialize order from the order slice, not the map.
func TestIDs_StableAcrossCalls(t *testing.T) {
	r, err := New(
		fakeProfile{id: domain.DiscoveryProfileANSTXT},
		fakeProfile{id: domain.DiscoveryProfileANSDNSAID},
	)
	require.NoError(t, err)

	for range 100 {
		assert.Equal(t, []domain.DiscoveryProfile{
			domain.DiscoveryProfileANSTXT,
			domain.DiscoveryProfileANSDNSAID,
		}, r.IDs())
	}
}
