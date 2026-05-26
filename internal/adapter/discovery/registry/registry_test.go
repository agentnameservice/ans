package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// fakeStyle is a minimal port.DiscoveryStyle test double. ID() is the
// only behavior the registry inspects; Records() returns nil so the
// fake stays cheap to instantiate in tables.
type fakeStyle struct{ id domain.DNSRecordStyle }

func (f fakeStyle) ID() domain.DNSRecordStyle { return f.id }
func (f fakeStyle) Records(*domain.AgentRegistration) []domain.ExpectedDNSRecord {
	return nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		styles    []port.DiscoveryStyle
		wantErr   string // substring; empty means success expected
		wantOrder []domain.DNSRecordStyle
	}{
		{
			name:      "empty_registry_constructs",
			styles:    nil,
			wantOrder: []domain.DNSRecordStyle{},
		},
		{
			name:      "single_valid_style",
			styles:    []port.DiscoveryStyle{fakeStyle{id: domain.DNSRecordStyleSVCB}},
			wantOrder: []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
		},
		{
			name: "two_valid_styles_preserve_argument_order",
			styles: []port.DiscoveryStyle{
				fakeStyle{id: domain.DNSRecordStyleTXT},
				fakeStyle{id: domain.DNSRecordStyleSVCB},
			},
			wantOrder: []domain.DNSRecordStyle{
				domain.DNSRecordStyleTXT,
				domain.DNSRecordStyleSVCB,
			},
		},
		{
			name: "duplicate_id_rejected",
			styles: []port.DiscoveryStyle{
				fakeStyle{id: domain.DNSRecordStyleSVCB},
				fakeStyle{id: domain.DNSRecordStyleSVCB},
			},
			wantErr: "duplicate style ID",
		},
		{
			name: "invalid_id_rejected",
			styles: []port.DiscoveryStyle{
				fakeStyle{id: domain.DNSRecordStyle("NOT_A_STYLE")},
			},
			wantErr: "is not a valid DNSRecordStyle",
		},
		{
			name: "invalid_id_rejected_after_valid_one",
			styles: []port.DiscoveryStyle{
				fakeStyle{id: domain.DNSRecordStyleSVCB},
				fakeStyle{id: domain.DNSRecordStyle("")},
			},
			wantErr: "is not a valid DNSRecordStyle",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.styles...)
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
	svcb := fakeStyle{id: domain.DNSRecordStyleSVCB}
	txt := fakeStyle{id: domain.DNSRecordStyleTXT}
	r, err := New(svcb, txt)
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      domain.DNSRecordStyle
		wantHit bool
		wantID  domain.DNSRecordStyle
	}{
		{name: "hit_svcb", id: domain.DNSRecordStyleSVCB, wantHit: true, wantID: domain.DNSRecordStyleSVCB},
		{name: "hit_txt", id: domain.DNSRecordStyleTXT, wantHit: true, wantID: domain.DNSRecordStyleTXT},
		{name: "miss_unknown_style", id: domain.DNSRecordStyle("UNKNOWN_FAMILY"), wantHit: false},
		{name: "miss_empty_id", id: domain.DNSRecordStyle(""), wantHit: false},
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
		fakeStyle{id: domain.DNSRecordStyleTXT},
		fakeStyle{id: domain.DNSRecordStyleSVCB},
	)
	require.NoError(t, err)

	first := r.IDs()
	first[0] = domain.DNSRecordStyle("MUTATED")

	second := r.IDs()
	assert.Equal(t, []domain.DNSRecordStyle{
		domain.DNSRecordStyleTXT,
		domain.DNSRecordStyleSVCB,
	}, second, "mutating one IDs() result must not affect a subsequent call")
}

// TestIDs_StableAcrossCalls pins that two consecutive IDs() calls return
// the same insertion order. Map iteration is non-deterministic in Go;
// the registry must materialize order from the order slice, not the map.
func TestIDs_StableAcrossCalls(t *testing.T) {
	r, err := New(
		fakeStyle{id: domain.DNSRecordStyleTXT},
		fakeStyle{id: domain.DNSRecordStyleSVCB},
	)
	require.NoError(t, err)

	for range 100 {
		assert.Equal(t, []domain.DNSRecordStyle{
			domain.DNSRecordStyleTXT,
			domain.DNSRecordStyleSVCB,
		}, r.IDs())
	}
}
