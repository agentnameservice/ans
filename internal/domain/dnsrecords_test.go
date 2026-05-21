package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeRequiredDNSRecords_WithoutCert(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 2, 3), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		// Force the union set so this fixture exercises both record
		// families: _ans TXT + Consolidated Approach SVCB. Tests below
		// cover the single-style emission paths.
		DNSRecordStyles: []DNSRecordStyle{DNSRecordStyleSVCB, DNSRecordStyleTXT},
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
		},
	}

	records := ComputeRequiredDNSRecords(reg)
	require.NotEmpty(t, records)

	// 2 endpoints → 2 _ans TXT + 1 HTTPS + 2 Consolidated Approach SVCB +
	// 1 badge TXT (no TLSA: no cert).
	var ansTxtCount, httpsCount, svcbCount, badgeCount, tlsaCount int
	for _, r := range records {
		switch r.Purpose {
		case PurposeDiscovery:
			switch r.Type {
			case DNSRecordTXT:
				ansTxtCount++
				assert.True(t, strings.HasPrefix(r.Name, "_ans."))
				assert.True(t, r.Required)
				assert.Contains(t, r.Value, "v=ans1")
				// Version is bare semver, not DNS-label form — TXT
				// payloads carry the machine-parseable semver directly.
				assert.Contains(t, r.Value, "version=1.2.3")
				assert.NotContains(t, r.Value, "v1.2.3", "no v-prefix in TXT payload")
				assert.NotContains(t, r.Value, "1-2-3", "no dash form anywhere")
			case DNSRecordSVCB:
				svcbCount++
				assert.Equal(t, "agent.example.com", r.Name,
					"Consolidated Approach SVCB at the bare FQDN, not at _ans.{fqdn}")
				assert.False(t, r.Required, "Consolidated Approach SVCB is MAY per §4.4.2")
				assert.Contains(t, r.Value, `1 . `, "ServiceMode (priority 1) with TargetName .")
				assert.Contains(t, r.Value, "alpn=", "alpn distinguishes protocols within the RRset")
				assert.Contains(t, r.Value, "port=443")
				// No agentCardContent submitted in this fixture, so
				// card-sha256 should be absent.
				assert.NotContains(t, r.Value, "card-sha256")
			case DNSRecordHTTPS:
				httpsCount++
				assert.Equal(t, "agent.example.com", r.Name,
					"HTTPS RR at the bare FQDN per §A.8.1")
				assert.False(t, r.Required,
					"HTTPS RR is opt-in: blocked by CNAME at @ when AHP fronts the apex")
				assert.Contains(t, r.Value, "alpn=h2")
			default:
				t.Errorf("unexpected discovery record type %q", r.Type)
			}
		case PurposeBadge:
			badgeCount++
			assert.Equal(t, DNSRecordTXT, r.Type)
			assert.True(t, strings.HasPrefix(r.Name, "_ans-badge."))
			// Both _ans and _ans-badge are required: badge-verifying
			// clients won't trust an agent that publishes _ans alone.
			assert.True(t, r.Required)
		case PurposeCertificateBinding:
			tlsaCount++
		}
	}

	assert.Equal(t, 2, ansTxtCount)
	assert.Equal(t, 1, httpsCount, "one HTTPS RR at the bare FQDN per §A.8.1")
	assert.Equal(t, 2, svcbCount, "one SVCB row per protocol at the bare FQDN")
	assert.Equal(t, 1, badgeCount)
	assert.Equal(t, 0, tlsaCount, "no cert → no TLSA record")
}

// TestComputeRequiredDNSRecords_StyleMatrix exercises every emission
// rule in one table. Each row pins the per-record-type shape the
// operator is asked to publish given a (styles, protocol,
// capabilitiesHash, agentURL) tuple. The matrix covers:
//
//   - {ANS_TXT} emits _ans TXT + HTTPS RR; no SVCB.
//   - {ANS_SVCB} emits SVCB only (no HTTPS RR — duplicate signalling).
//   - {ANS_SVCB, ANS_TXT} emits the union.
//   - SVCB SvcParam composition: wk= (per-protocol), port= (from URL),
//     card-sha256= (only when CapabilitiesHash is set).
//   - svcbPortFor: explicit non-443 port flows through, default https
//     URLs fall back to 443.
//   - Empty styles (nil slice) coerces to the default ({ANS_SVCB}).
//   - All-invalid styles set still produces records (defensive
//     fallback in the domain layer; the service rejects bad inputs).
func TestComputeRequiredDNSRecords_StyleMatrix(t *testing.T) {
	const cardHex = "098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantCardBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name             string
		styles           []DNSRecordStyle
		protocol         Protocol
		agentURL         string
		capabilitiesHash string
		wantHTTPS        bool
		wantSVCB         bool
		wantLegacyTXT    bool
		wantSVCBPort     string // substring expected in SVCB value (e.g. "port=443")
		wantSVCBWk       string // "" means SVCB MUST NOT contain "wk="
		wantSVCBCard     string // "" means SVCB MUST NOT contain "card-sha256"
	}{
		{
			name:          "ans_txt_only_emits_https_rr_no_svcb",
			styles:        []DNSRecordStyle{DNSRecordStyleTXT},
			protocol:      ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
		},
		{
			name:         "ans_svcb_only_omits_https_rr",
			styles:       []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:     ProtocolA2A,
			agentURL:     "https://agent.example.com",
			wantSVCB:     true,
			wantSVCBPort: "port=443",
			wantSVCBWk:   "wk=agent-card.json",
		},
		{
			name:          "union_emits_both_families",
			styles:        []DNSRecordStyle{DNSRecordStyleSVCB, DNSRecordStyleTXT},
			protocol:      ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
			wantSVCB:      true,
			wantSVCBPort:  "port=443",
			wantSVCBWk:    "wk=agent-card.json",
		},
		{
			name:         "svcb_mcp_wk_mcp_json",
			styles:       []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:     ProtocolMCP,
			agentURL:     "https://agent.example.com/mcp",
			wantSVCB:     true,
			wantSVCBPort: "port=443",
			wantSVCBWk:   "wk=mcp.json",
		},
		{
			name:         "svcb_http_api_omits_wk",
			styles:       []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:     ProtocolHTTPAPI,
			agentURL:     "https://agent.example.com",
			wantSVCB:     true,
			wantSVCBPort: "port=443",
			// HTTP-API has no per-protocol metadata file convention.
		},
		{
			name:             "svcb_card_sha256_present_when_set",
			styles:           []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:         ProtocolA2A,
			agentURL:         "https://agent.example.com",
			capabilitiesHash: cardHex,
			wantSVCB:         true,
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=agent-card.json",
			wantSVCBCard:     "card-sha256=" + wantCardBase64,
		},
		{
			name:         "svcb_non_443_port_from_url",
			styles:       []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:     ProtocolA2A,
			agentURL:     "https://agent.example.com:8443",
			wantSVCB:     true,
			wantSVCBPort: "port=8443",
			wantSVCBWk:   "wk=agent-card.json",
		},
		{
			name:         "svcb_http_scheme_defaults_port_80",
			styles:       []DNSRecordStyle{DNSRecordStyleSVCB},
			protocol:     ProtocolA2A,
			agentURL:     "http://agent.example.com",
			wantSVCB:     true,
			wantSVCBPort: "port=80",
			wantSVCBWk:   "wk=agent-card.json",
		},
		{
			name:         "empty_styles_coerces_to_default",
			styles:       nil,
			protocol:     ProtocolA2A,
			agentURL:     "https://agent.example.com",
			wantSVCB:     true,
			wantSVCBPort: "port=443",
			wantSVCBWk:   "wk=agent-card.json",
		},
		{
			name:         "all_invalid_styles_falls_back_to_default",
			styles:       []DNSRecordStyle{DNSRecordStyle("garbage"), DNSRecordStyle("nonsense")},
			protocol:     ProtocolA2A,
			agentURL:     "https://agent.example.com",
			wantSVCB:     true,
			wantSVCBPort: "port=443",
			wantSVCBWk:   "wk=agent-card.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
			reg := &AgentRegistration{
				AnsName:          ansName,
				DNSRecordStyles:  tc.styles,
				CapabilitiesHash: tc.capabilitiesHash,
				Endpoints: []AgentEndpoint{
					{Protocol: tc.protocol, AgentURL: tc.agentURL},
				},
			}
			records := ComputeRequiredDNSRecords(reg)

			var sawHTTPS, sawSVCB, sawLegacyTXT bool
			var svcbValue string
			for _, r := range records {
				switch r.Type {
				case DNSRecordHTTPS:
					sawHTTPS = true
				case DNSRecordSVCB:
					sawSVCB = true
					svcbValue = r.Value
				case DNSRecordTXT:
					if strings.HasPrefix(r.Name, "_ans.") {
						sawLegacyTXT = true
					}
				}
			}

			assert.Equal(t, tc.wantHTTPS, sawHTTPS, "HTTPS RR presence")
			assert.Equal(t, tc.wantSVCB, sawSVCB, "SVCB row presence")
			assert.Equal(t, tc.wantLegacyTXT, sawLegacyTXT, "_ans TXT presence")

			if tc.wantSVCB {
				assert.Contains(t, svcbValue, tc.wantSVCBPort,
					"SVCB port SvcParam mismatch")
				if tc.wantSVCBWk != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBWk, "SVCB wk SvcParam mismatch")
				} else {
					assert.NotContains(t, svcbValue, "wk=",
						"SVCB MUST NOT carry wk= when protocol has no metadata convention")
				}
				if tc.wantSVCBCard != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBCard, "SVCB card-sha256 SvcParam mismatch")
				} else {
					assert.NotContains(t, svcbValue, "card-sha256",
						"SVCB MUST NOT carry card-sha256 when CapabilitiesHash is empty")
				}
			}
		})
	}
}

// TestCapabilitiesHashBase64URL pins the hex→base64url conversion.
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
		{
			name: "empty_input_empty_output",
			in:   "",
			want: "",
		},
		{
			name: "malformed_hex_returns_empty",
			in:   "not hex",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilitiesHashBase64URL(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestWkPathFor pins the per-protocol well-known suffix mapping.
func TestWkPathFor(t *testing.T) {
	tests := []struct {
		p    Protocol
		want string
	}{
		{ProtocolA2A, "agent-card.json"},
		{ProtocolMCP, "mcp.json"},
		{ProtocolHTTPAPI, ""},
		{Protocol("UNKNOWN"), ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.p), func(t *testing.T) {
			assert.Equal(t, tc.want, wkPathFor(tc.p))
		})
	}
}

// TestValidDNSRecordStyles pins the canonical valid set of
// DNSRecordStyle values returned by the helper used in the V2
// INVALID_DNS_RECORD_STYLE error message and (eventually) by spec
// generation tooling. Order and contents are stable so an external
// client's error-message fixtures can match.
func TestValidDNSRecordStyles(t *testing.T) {
	got := ValidDNSRecordStyles()
	want := []string{"ANS_SVCB", "ANS_TXT"}
	assert.Equal(t, want, got)
}

// TestDefaultDNSRecordStyles pins the default set applied when a V2
// register request omits dnsRecordStyles. {ANS_SVCB} per §4.4.2.
func TestDefaultDNSRecordStyles(t *testing.T) {
	got := DefaultDNSRecordStyles()
	want := []DNSRecordStyle{DNSRecordStyleSVCB}
	assert.Equal(t, want, got)
}

// TestSVCBPortFor pins the agentURL → port resolution that drives the
// SVCB `port=` SvcParam. Covers https-default, http-default, explicit
// port, malformed URL, and empty input.
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

func TestComputeRequiredDNSRecords_WithCert(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
		},
		ServerCert: &ByocServerCertificate{Fingerprint: "abcdef"},
	}

	records := ComputeRequiredDNSRecords(reg)

	var tlsaFound bool
	for _, r := range records {
		if r.Purpose == PurposeCertificateBinding {
			tlsaFound = true
			assert.Equal(t, DNSRecordTLSA, r.Type)
			assert.Contains(t, r.Name, "_443._tcp.")
			assert.Contains(t, r.Value, "abcdef")
			// Required=false: TLSA is only meaningful when the
			// operator's zone is DNSSEC-signed, which is a runtime
			// property the domain layer can't know. The verifier
			// enforces a post-verify rule: if the TLSA response was
			// DNSSEC-validated, its value must match. See
			// RegistrationService.verifyDNSRecords.
			assert.False(t, r.Required)
		}
	}
	assert.True(t, tlsaFound)
}

func TestComputeRequiredDNSRecords_NoEndpoints(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{AnsName: ansName}
	records := ComputeRequiredDNSRecords(reg)
	assert.Empty(t, records)
}

func TestProtocolToANSValue(t *testing.T) {
	assert.Equal(t, "a2a", protocolToANSValue(ProtocolA2A))
	assert.Equal(t, "mcp", protocolToANSValue(ProtocolMCP))
	assert.Equal(t, "http-api", protocolToANSValue(ProtocolHTTPAPI))
	assert.Equal(t, "UNKNOWN", protocolToANSValue(Protocol("UNKNOWN")))
}
