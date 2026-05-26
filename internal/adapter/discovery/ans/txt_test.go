package ans

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
)

func TestTXTStyle_ID(t *testing.T) {
	assert.Equal(t, domain.DNSRecordStyleTXT, TXTStyle{}.ID())
}

func TestTXTStyle_Records(t *testing.T) {
	tests := []struct {
		name        string
		eps         []domain.AgentEndpoint
		wantTXTRows int
		wantHTTPS   bool
		// when wantTXTRows > 0, assertions on the first TXT row's value:
		wantInValue []string
		wantNotIn   []string
	}{
		{
			name: "one_a2a_endpoint_emits_one_ans_txt_and_one_https_rr",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
			},
			wantTXTRows: 1,
			wantHTTPS:   true,
			wantInValue: []string{
				"v=ans1",
				"version=1.0.0",
				"p=a2a",
				"mode=direct",
				"url=https://agent.example.com/a2a",
			},
			wantNotIn: []string{"v1.0.0", "1-0-0"},
		},
		{
			name: "two_endpoints_emit_two_ans_txt_rows_one_https_rr",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantTXTRows: 2,
			wantHTTPS:   true,
		},
		{
			// Behavioral correction bundled in this refactor: zero
			// endpoints with ANS_TXT previously emitted an HTTPS RR
			// with no `_ans` TXT companions — a service binding for a
			// non-existent agent. The gate on len(endpoints) > 0
			// closes that degenerate output.
			name:        "zero_endpoints_emits_no_records_no_https_rr",
			eps:         nil,
			wantTXTRows: 0,
			wantHTTPS:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := mustReg(t, "agent.example.com", tc.eps, nil)
			records := TXTStyle{}.Records(reg)

			var txtRows int
			var httpsRows int
			var firstTXTValue string
			for _, r := range records {
				if r.Type == domain.DNSRecordTXT && strings.HasPrefix(r.Name, "_ans.") {
					if txtRows == 0 {
						firstTXTValue = r.Value
					}
					txtRows++
					assert.True(t, r.Required, "_ans TXT must be Required=true")
					assert.Equal(t, domain.PurposeDiscovery, r.Purpose)
					assert.Equal(t, 3600, r.TTL)
				}
				if r.Type == domain.DNSRecordHTTPS {
					httpsRows++
					assert.Equal(t, "agent.example.com", r.Name, "HTTPS RR lives at the bare FQDN")
					assert.False(t, r.Required, "HTTPS RR is non-required (CNAME-at-apex precludes publishing)")
					assert.Contains(t, r.Value, "alpn=h2")
				}
			}
			assert.Equal(t, tc.wantTXTRows, txtRows, "_ans TXT row count")
			if tc.wantHTTPS {
				assert.Equal(t, 1, httpsRows, "exactly one HTTPS RR per registration")
			} else {
				assert.Zero(t, httpsRows, "zero endpoints must emit zero HTTPS RRs")
			}

			for _, want := range tc.wantInValue {
				assert.Contains(t, firstTXTValue, want)
			}
			for _, notWant := range tc.wantNotIn {
				assert.NotContains(t, firstTXTValue, notWant)
			}
		})
	}
}

// TestTXTStyle_RecordsIncludesFamilyTrustRecords pins that TXTStyle is
// self-contained in the same way as SVCBStyle: it emits the family
// badge and TLSA records.
func TestTXTStyle_RecordsIncludesFamilyTrustRecords(t *testing.T) {
	reg := mustReg(t, "agent.example.com",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		&domain.ByocServerCertificate{Fingerprint: "deadbeef"})

	records := TXTStyle{}.Records(reg)

	var sawBadge, sawTLSA bool
	for _, r := range records {
		if r.Purpose == domain.PurposeBadge {
			sawBadge = true
		}
		if r.Purpose == domain.PurposeCertificateBinding {
			sawTLSA = true
		}
	}
	assert.True(t, sawBadge)
	assert.True(t, sawTLSA)
}

// TestTXTStyle_NoEndpointsSkipsAllFamilyAndDiscoveryRecords pins the
// existing-behavior contract that an empty endpoint list produces an
// empty record set when ServerCert is also nil. Zero endpoints + nil
// cert means there's nothing meaningful to publish.
func TestTXTStyle_NoEndpointsSkipsAllFamilyAndDiscoveryRecords(t *testing.T) {
	reg := mustReg(t, "agent.example.com", nil, nil)
	records := TXTStyle{}.Records(reg)
	require.Empty(t, records)
}

// TestTXTStyle_ZeroEndpointsWithCertOnlyEmitsTLSA pins that even with
// zero endpoints, a registration that has a server cert still gets the
// TLSA record. (The badge requires endpoints; TLSA does not.)
func TestTXTStyle_ZeroEndpointsWithCertOnlyEmitsTLSA(t *testing.T) {
	reg := mustReg(t, "agent.example.com", nil,
		&domain.ByocServerCertificate{Fingerprint: "abcd"})
	records := TXTStyle{}.Records(reg)
	require.Len(t, records, 1)
	assert.Equal(t, domain.DNSRecordTLSA, records[0].Type)
}
