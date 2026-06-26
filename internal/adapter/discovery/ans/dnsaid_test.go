package ans

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
)

func mustReg(t *testing.T, host string, eps []domain.AgentEndpoint, cert *domain.ByocServerCertificate) *domain.AgentRegistration {
	t.Helper()
	v, err := domain.NewSemVer(1, 0, 0)
	require.NoError(t, err)
	ansName, err := domain.NewAnsName(v, host)
	require.NoError(t, err)
	return &domain.AgentRegistration{
		AnsName:    ansName,
		Endpoints:  eps,
		ServerCert: cert,
	}
}

func TestDNSAIDProfile_ID(t *testing.T) {
	assert.Equal(t, domain.DiscoveryProfileANSDNSAID, DNSAIDProfile{}.ID())
}

// TestDNSAIDProfile_Records walks the SvcParam composition rules the
// DNS-AID-aligned profile emits: alpn, port, bap (key65402, always), cap
// (key65400, from metadataUrl), cap-sha256 (key65401, from metadataHash),
// and the well-known suffix (key65409, derived from the metadataUrl
// path). The well-known suffix is sourced from where the metadata
// document actually lives (metadataUrl), NOT from the protocol — an
// endpoint with no metadataUrl carries no cap and no well-known. All
// custom params ride in RFC 9460 §14.3.1 Private Use keyNNNNN form, never
// the named DNS-AID forms (cap= / bap= / well-known=), which the
// miekg/dns zone parser rejects.
func TestDNSAIDProfile_Records(t *testing.T) {
	const sampleMetadataHash = "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantSampleCapBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name        string
		eps         []domain.AgentEndpoint
		wantCount   int
		wantAlpn    string // e.g. "alpn=a2a"
		wantBap     string // e.g. "key65402=a2a"
		wantPort    string // e.g. "port=443"
		wantCap     string // "" → key65400 MUST be absent
		wantCapSHA  string // "" → key65401 MUST be absent
		wantWk      string // "" → key65409 MUST be absent
		wantNotPort string
	}{
		{
			name: "a2a_no_metadata_url_omits_cap_and_wk",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"},
			},
			wantCount: 1,
			wantAlpn:  "alpn=a2a",
			wantBap:   "key65402=a2a",
			wantPort:  "port=443",
		},
		{
			name: "mcp_no_metadata_url",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 1,
			wantAlpn:  "alpn=mcp",
			wantBap:   "key65402=mcp",
			wantPort:  "port=443",
		},
		{
			name: "http_api_maps_alpn_and_bap_to_x_http",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolHTTPAPI, AgentURL: "https://agent.example.com"},
			},
			wantCount: 1,
			wantAlpn:  "alpn=x-http",
			wantBap:   "key65402=x-http",
			wantPort:  "port=443",
		},
		{
			name: "cap_and_well_known_from_metadata_url",
			eps: []domain.AgentEndpoint{
				{
					Protocol:    domain.ProtocolMCP,
					AgentURL:    "https://agent.example.com/mcp",
					MetadataURL: "https://agent.example.com/.well-known/mcp.json",
				},
			},
			wantCount: 1,
			wantAlpn:  "alpn=mcp",
			wantBap:   "key65402=mcp",
			wantPort:  "port=443",
			wantCap:   "key65400=https://agent.example.com/.well-known/mcp.json",
			wantWk:    "key65409=mcp.json",
		},
		{
			name: "cap_sha256_present_when_metadata_hash_set",
			eps: []domain.AgentEndpoint{
				{
					Protocol:     domain.ProtocolA2A,
					AgentURL:     "https://agent.example.com",
					MetadataURL:  "https://agent.example.com/.well-known/agent-card.json",
					MetadataHash: sampleMetadataHash,
				},
			},
			wantCount:  1,
			wantAlpn:   "alpn=a2a",
			wantBap:    "key65402=a2a",
			wantPort:   "port=443",
			wantCap:    "key65400=https://agent.example.com/.well-known/agent-card.json",
			wantCapSHA: "key65401=" + wantSampleCapBase64,
			wantWk:     "key65409=agent-card.json",
		},
		{
			name: "off_path_metadata_url_emits_cap_but_no_well_known",
			eps: []domain.AgentEndpoint{
				{
					Protocol:    domain.ProtocolMCP,
					AgentURL:    "https://agent.example.com/mcp",
					MetadataURL: "https://agent.example.com/metadata/mcp.json",
				},
			},
			wantCount: 1,
			wantAlpn:  "alpn=mcp",
			wantBap:   "key65402=mcp",
			wantPort:  "port=443",
			wantCap:   "key65400=https://agent.example.com/metadata/mcp.json",
			// metadataUrl not under /.well-known/ → no key65409
		},
		{
			name: "non_443_port_from_url_authority",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com:8443"},
			},
			wantCount:   1,
			wantAlpn:    "alpn=a2a",
			wantBap:     "key65402=a2a",
			wantPort:    "port=8443",
			wantNotPort: "port=443",
		},
		{
			name: "http_scheme_defaults_port_80",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "http://agent.example.com"},
			},
			wantCount: 1,
			wantAlpn:  "alpn=a2a",
			wantBap:   "key65402=a2a",
			wantPort:  "port=80",
		},
		{
			// First row asserted below; pins count and that row order
			// tracks endpoint order (A2A first).
			name: "two_endpoints_emits_two_svcb_rows",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 2,
			wantAlpn:  "alpn=a2a",
			wantBap:   "key65402=a2a",
			wantPort:  "port=443",
		},
		{
			name:      "zero_endpoints_emits_no_svcb_rows",
			eps:       nil,
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := mustReg(t, "agent.example.com", tc.eps, nil)
			records := DNSAIDProfile{}.Records(reg)

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
			assert.True(t, r.Required, "DNSAID always returns Required=true; service post-processes for the union case")
			assert.Contains(t, r.Value, `1 . `, "ServiceMode (priority 1) with TargetName .")
			assert.Contains(t, r.Value, tc.wantAlpn)
			assert.Contains(t, r.Value, tc.wantBap, "bap (key65402) MUST be present on every row")
			assert.Contains(t, r.Value, tc.wantPort)
			if tc.wantNotPort != "" {
				assert.NotContains(t, r.Value, tc.wantNotPort)
			}
			if tc.wantCap != "" {
				assert.Contains(t, r.Value, tc.wantCap)
			} else {
				assert.NotContains(t, r.Value, "key65400=", "key65400 (cap) MUST be absent without a metadataUrl")
			}
			if tc.wantCapSHA != "" {
				assert.Contains(t, r.Value, tc.wantCapSHA)
			} else {
				assert.NotContains(t, r.Value, "key65401=", "key65401 (cap-sha256) MUST be absent without a metadataHash")
			}
			if tc.wantWk != "" {
				assert.Contains(t, r.Value, tc.wantWk)
			} else {
				assert.NotContains(t, r.Value, "key65409=", "key65409 (well-known) MUST be absent unless metadataUrl is at /.well-known/")
			}
			// Named-form regression guards: never the unpublishable DNS-AID
			// named forms; only the keyNNNNN Private Use presentation.
			assert.NotContains(t, r.Value, "cap=", "named `cap=` MUST NOT appear; key65400 is the publishable form")
			assert.NotContains(t, r.Value, "bap=", "named `bap=` MUST NOT appear; key65402 is the publishable form")
			assert.NotContains(t, r.Value, "cap-sha256", "named `cap-sha256=` MUST NOT appear; key65401 is the publishable form")
			assert.NotContains(t, r.Value, "well-known=", "named `well-known=` MUST NOT appear; key65409 is the publishable form")
		})
	}
}

// TestDNSAIDProfile_RecordsIncludesFamilyTrustRecords pins that
// DNSAIDProfile is self-contained — it emits the family's badge and TLSA
// records too, so registering ANS_DNSAID alone produces a complete set
// without any service-layer trust-record plumbing.
func TestDNSAIDProfile_RecordsIncludesFamilyTrustRecords(t *testing.T) {
	reg := mustReg(t, "agent.example.com",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		&domain.ByocServerCertificate{Fingerprint: "deadbeef"})

	records := DNSAIDProfile{}.Records(reg)

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
	assert.True(t, sawBadge, "DNSAID profile must include the family `_ans-badge` record")
	assert.True(t, sawTLSA, "DNSAID profile must include the TLSA record when ServerCert is set")
}

func TestMetadataHashToCapSHA256(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "valid_sha256_prefixed_hex_lowers_to_base64url",
			in:   "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27",
			want: "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc",
		},
		{
			name: "all_zeros_round_trip",
			in:   "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
			want: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{name: "empty_input_empty_output", in: "", want: ""},
		{name: "missing_sha256_prefix_returns_empty", in: "098d650cc6d2", want: ""},
		{name: "wrong_prefix_returns_empty", in: "SHA1:abc", want: ""},
		{name: "malformed_hex_after_prefix_returns_empty", in: "SHA256:not hex", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, metadataHashToCapSHA256(tc.in))
		})
	}
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
