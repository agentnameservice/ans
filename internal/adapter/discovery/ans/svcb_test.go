package ans

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
)

func mustReg(t *testing.T, host string, eps []domain.AgentEndpoint, capHash string, cert *domain.ByocServerCertificate) *domain.AgentRegistration {
	t.Helper()
	v, err := domain.NewSemVer(1, 0, 0)
	require.NoError(t, err)
	ansName, err := domain.NewAnsName(v, host)
	require.NoError(t, err)
	return &domain.AgentRegistration{
		AnsName:          ansName,
		Endpoints:        eps,
		CapabilitiesHash: capHash,
		ServerCert:       cert,
	}
}

func TestSVCBStyle_ID(t *testing.T) {
	assert.Equal(t, domain.DNSRecordStyleSVCB, SVCBStyle{}.ID())
}

// TestSVCBStyle_Records walks the SvcParam composition rules (alpn /
// port / wk / card-sha256) the consolidated-draft fixes, plus the
// always-Required default the service walker post-processes.
func TestSVCBStyle_Records(t *testing.T) {
	const cardHex = "098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantCardBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name        string
		eps         []domain.AgentEndpoint
		capHash     string
		wantCount   int // svcb rows expected
		wantPort    string
		wantAlpn    string
		wantWk      string // empty means MUST NOT appear
		wantCard    string // empty means MUST NOT appear
		wantNotPort string // value MUST NOT contain this string (e.g. wrong default)
	}{
		{
			name: "a2a_https_default_port",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"},
			},
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=a2a",
			wantWk:    "wk=agent-card.json",
		},
		{
			name: "mcp_emits_mcp_json_well_known",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=mcp",
			wantWk:    "wk=mcp.json",
		},
		{
			name: "http_api_omits_wk",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolHTTPAPI, AgentURL: "https://agent.example.com"},
			},
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=http-api",
			wantWk:    "", // HTTP-API has no per-protocol metadata file
		},
		{
			name: "card_sha256_present_when_capabilities_hash_set",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"},
			},
			capHash:   cardHex,
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=a2a",
			wantWk:    "wk=agent-card.json",
			wantCard:  "card-sha256=" + wantCardBase64,
		},
		{
			name: "non_443_port_from_url_authority",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com:8443"},
			},
			wantCount:   1,
			wantPort:    "port=8443",
			wantAlpn:    "alpn=a2a",
			wantWk:      "wk=agent-card.json",
			wantNotPort: "port=443",
		},
		{
			name: "http_scheme_defaults_port_80",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "http://agent.example.com"},
			},
			wantCount: 1,
			wantPort:  "port=80",
			wantAlpn:  "alpn=a2a",
			wantWk:    "wk=agent-card.json",
		},
		{
			// First row asserted below; assertions on the A2A protocol's
			// SvcParam composition (port, alpn, wk). The MCP row's wk=mcp.json
			// is covered by the dedicated mcp test case above; here we only
			// pin that the count is right and the row order tracks endpoint
			// order.
			name: "two_endpoints_emits_two_svcb_rows",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 2,
			wantPort:  "port=443",
			wantAlpn:  "alpn=a2a",
			wantWk:    "wk=agent-card.json",
		},
		{
			name:      "zero_endpoints_emits_no_svcb_rows",
			eps:       nil,
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := mustReg(t, "agent.example.com", tc.eps, tc.capHash, nil)
			records := SVCBStyle{}.Records(reg)

			var svcbRows []domain.ExpectedDNSRecord
			for _, r := range records {
				if r.Type == domain.DNSRecordSVCB {
					svcbRows = append(svcbRows, r)
				}
			}
			require.Len(t, svcbRows, tc.wantCount, "SVCB row count")

			if tc.wantCount == 0 {
				return
			}

			r := svcbRows[0]
			assert.Equal(t, "agent.example.com", r.Name, "SVCB lives at the bare FQDN")
			assert.Equal(t, domain.PurposeDiscovery, r.Purpose)
			assert.Equal(t, 3600, r.TTL)
			assert.True(t, r.Required, "SVCB always returns Required=true; service post-processes for the union case")
			assert.Contains(t, r.Value, `1 . `, "ServiceMode (priority 1) with TargetName .")
			if tc.wantAlpn != "" {
				assert.Contains(t, r.Value, tc.wantAlpn)
			}
			if tc.wantPort != "" {
				assert.Contains(t, r.Value, tc.wantPort)
			}
			if tc.wantNotPort != "" {
				assert.NotContains(t, r.Value, tc.wantNotPort)
			}
			if tc.wantWk != "" {
				assert.Contains(t, r.Value, tc.wantWk)
			} else {
				assert.NotContains(t, r.Value, "wk=", "wk= MUST be absent for protocols with no metadata file convention")
			}
			if tc.wantCard != "" {
				assert.Contains(t, r.Value, tc.wantCard)
			} else {
				assert.NotContains(t, r.Value, "card-sha256", "card-sha256 MUST be absent when CapabilitiesHash is empty")
			}
		})
	}
}

// TestSVCBStyle_RecordsIncludesFamilyTrustRecords pins that SVCBStyle
// is self-contained — it emits the family's badge and TLSA records too,
// so registering ANS_SVCB alone produces a complete set without any
// service-layer trust-record plumbing.
func TestSVCBStyle_RecordsIncludesFamilyTrustRecords(t *testing.T) {
	reg := mustReg(t, "agent.example.com",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		"", &domain.ByocServerCertificate{Fingerprint: "deadbeef"})

	records := SVCBStyle{}.Records(reg)

	var sawBadge, sawTLSA bool
	for _, r := range records {
		if r.Purpose == domain.PurposeBadge {
			sawBadge = true
			assert.True(t, strings.HasPrefix(r.Name, "_ans-badge."))
		}
		if r.Purpose == domain.PurposeCertificateBinding {
			sawTLSA = true
			assert.True(t, strings.HasPrefix(r.Name, "_443._tcp."))
		}
	}
	assert.True(t, sawBadge, "SVCB style must include the family `_ans-badge` record")
	assert.True(t, sawTLSA, "SVCB style must include the TLSA record when ServerCert is set")
}

func TestSVCBPortFor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "https_default_443", in: "https://agent.example.com", want: 443},
		{name: "http_default_80", in: "http://agent.example.com", want: 80},
		{name: "explicit_port_8443", in: "https://agent.example.com:8443", want: 8443},
		{name: "explicit_port_8080_http", in: "http://agent.example.com:8080", want: 8080},
		{name: "with_path_keeps_port", in: "https://agent.example.com:9443/a2a", want: 9443},
		{name: "empty_url_defaults_443", in: "", want: 443},
		{name: "malformed_url_defaults_443", in: "://not-a-url", want: 443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, svcbPortFor(tc.in))
		})
	}
}

func TestCapabilitiesHashBase64URL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "live_webmesh_trust_card_digest",
			in:   "098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27",
			want: "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc",
		},
		{
			name: "all_zeros",
			in:   "0000000000000000000000000000000000000000000000000000000000000000",
			want: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{name: "empty_input_empty_output", in: "", want: ""},
		{name: "malformed_hex_returns_empty", in: "not hex", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, capabilitiesHashBase64URL(tc.in))
		})
	}
}
