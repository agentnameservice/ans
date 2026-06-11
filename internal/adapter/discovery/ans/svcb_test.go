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

func TestSVCBProfile_ID(t *testing.T) {
	assert.Equal(t, domain.DiscoveryProfileANSSVCB, SVCBProfile{}.ID())
}

// TestSVCBProfile_Records walks the SvcParam composition rules (alpn /
// port / key65280 / key65281) the consolidated-draft fixes, plus the
// always-Required default the service walker post-processes. The
// well-known suffix and capability digest ride in RFC 9460 §14.3.1
// Private Use keyNNNNN SvcParams (key65280 / key65281), not the named
// forms `wk=` / `card-sha256=` — those have no IANA code point and the
// miekg/dns zone parser rejects them.
func TestSVCBProfile_Records(t *testing.T) {
	const sampleMetadataHash = "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantSampleCapBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name        string
		eps         []domain.AgentEndpoint
		wantCount   int // svcb rows expected
		wantPort    string
		wantAlpn    string
		wantWk      string // empty means MUST NOT appear (well-known suffix in key65280)
		wantCap     string // empty means MUST NOT appear (capability digest in key65281)
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
			wantWk:    "key65280=agent-card.json",
		},
		{
			name: "mcp_emits_mcp_json_well_known",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=mcp",
			wantWk:    "key65280=mcp.json",
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
			name: "cap_sha256_present_when_endpoint_metadata_hash_set",
			eps: []domain.AgentEndpoint{
				{
					Protocol:     domain.ProtocolA2A,
					AgentURL:     "https://agent.example.com",
					MetadataHash: sampleMetadataHash,
				},
			},
			wantCount: 1,
			wantPort:  "port=443",
			wantAlpn:  "alpn=a2a",
			wantWk:    "key65280=agent-card.json",
			wantCap:   "key65281=" + wantSampleCapBase64,
		},
		{
			name: "non_443_port_from_url_authority",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com:8443"},
			},
			wantCount:   1,
			wantPort:    "port=8443",
			wantAlpn:    "alpn=a2a",
			wantWk:      "key65280=agent-card.json",
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
			wantWk:    "key65280=agent-card.json",
		},
		{
			// First row asserted below; assertions on the A2A protocol's
			// SvcParam composition (port, alpn, key65280). The MCP row's
			// key65280=mcp.json is covered by the dedicated mcp test case
			// above; here we only pin that the count is right and the row
			// order tracks endpoint order.
			name: "two_endpoints_emits_two_svcb_rows",
			eps: []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			},
			wantCount: 2,
			wantPort:  "port=443",
			wantAlpn:  "alpn=a2a",
			wantWk:    "key65280=agent-card.json",
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
			records := SVCBProfile{}.Records(reg)

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
				assert.NotContains(t, r.Value, "key65280=",
					"key65280 (well-known suffix) MUST be absent for protocols with no metadata file convention")
			}
			if tc.wantCap != "" {
				assert.Contains(t, r.Value, tc.wantCap)
			} else {
				assert.NotContains(t, r.Value, "key65281=",
					"key65281 (capability digest) MUST be absent when endpoint MetadataHash is empty")
			}
			// Named-form regression guards: every SVCB value must use the
			// keyNNNNN Private Use presentation, never the unpublishable
			// named forms. miekg/dns rejects `wk=` / `card-sha256=` at the
			// zone parser (proven empirically), so a backslide here strands
			// agents in PENDING_DNS under the lookup verifier.
			assert.NotContains(t, r.Value, "wk=",
				"named `wk=` SvcParam MUST NOT appear; key65280 is the publishable form")
			assert.NotContains(t, r.Value, "cap-sha256",
				"named `cap-sha256=` SvcParam MUST NOT appear; key65281 is the publishable form")
			assert.NotContains(t, r.Value, "card-sha256",
				"legacy `card-sha256=` SvcParam MUST NOT appear; key65281 is the publishable form")
		})
	}
}

// TestSVCBProfile_RecordsIncludesFamilyTrustRecords pins that SVCBProfile
// is self-contained — it emits the family's badge and TLSA records too,
// so registering ANS_SVCB alone produces a complete set without any
// service-layer trust-record plumbing.
func TestSVCBProfile_RecordsIncludesFamilyTrustRecords(t *testing.T) {
	reg := mustReg(t, "agent.example.com",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		&domain.ByocServerCertificate{Fingerprint: "deadbeef"})

	records := SVCBProfile{}.Records(reg)

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
