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
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
		},
	}

	records := ComputeRequiredDNSRecords(reg)
	require.NotEmpty(t, records)

	// 2 endpoints → 2 _ans TXT + 2 Consolidated Approach SVCB +
	// 1 badge TXT (no TLSA: no cert).
	var ansTxtCount, svcbCount, badgeCount, tlsaCount int
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
	assert.Equal(t, 2, svcbCount, "one SVCB row per protocol at the bare FQDN")
	assert.Equal(t, 1, badgeCount)
	assert.Equal(t, 0, tlsaCount, "no cert → no TLSA record")
}

// TestComputeRequiredDNSRecords_SVCBWkPath pins the per-protocol `wk=`
// SvcParam value the Consolidated Approach SVCB carries. A2A maps to
// `agent-card.json` (IANA-registered); MCP maps to `mcp.json` (de-facto
// convention). Suffix-only — the consolidated draft's primary examples
// use the suffix and clients prepend `/.well-known/`.
func TestComputeRequiredDNSRecords_SVCBWkPath(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com"},
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
		},
	}
	records := ComputeRequiredDNSRecords(reg)

	for _, r := range records {
		if r.Type != DNSRecordSVCB {
			continue
		}
		switch {
		case strings.Contains(r.Value, `alpn=a2a`):
			assert.Contains(t, r.Value, `wk=agent-card.json`)
		case strings.Contains(r.Value, `alpn=mcp`):
			assert.Contains(t, r.Value, `wk=mcp.json`)
		default:
			t.Errorf("SVCB row missing recognized alpn: %q", r.Value)
		}
	}
}

// TestComputeRequiredDNSRecords_SVCBCardSHA256_PresentWhenSet verifies
// that an agent registered with agentCardContent emits SVCB rows whose
// card-sha256 SvcParam is the base64url form of reg.CapabilitiesHash.
// This is the DNS half of §4.4.2's three-way cross-check (the live
// Trust Card body, the TL-sealed capabilities_hash, and the SVCB
// card-sha256 all commit to the same SHA-256).
func TestComputeRequiredDNSRecords_SVCBCardSHA256_PresentWhenSet(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	// Fixture digest used across the cross-check — the same hex appears
	// in the TL event's attestations.metadataHashes.capabilitiesHash.
	hexDigest := "098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	wantBase64 := "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"
	reg := &AgentRegistration{
		AnsName:          ansName,
		CapabilitiesHash: hexDigest,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com"},
		},
	}
	records := ComputeRequiredDNSRecords(reg)

	var sawSVCB bool
	for _, r := range records {
		if r.Type != DNSRecordSVCB {
			continue
		}
		sawSVCB = true
		assert.Contains(t, r.Value, `card-sha256=`+wantBase64,
			"SVCB card-sha256 must be base64url(decoded hex of reg.CapabilitiesHash)")
	}
	assert.True(t, sawSVCB, "expected at least one SVCB row")
}

// TestComputeRequiredDNSRecords_SVCBCardSHA256_AbsentWhenUnset verifies
// the spec-conformant "no agentCardContent submitted" path: the SVCB
// row omits the card-sha256 SvcParam entirely. A verifier seeing no
// SvcParam falls back to TOFU on first Trust Card fetch (§4.4.2).
func TestComputeRequiredDNSRecords_SVCBCardSHA256_AbsentWhenUnset(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com"},
		},
	}
	records := ComputeRequiredDNSRecords(reg)
	for _, r := range records {
		if r.Type == DNSRecordSVCB {
			assert.NotContains(t, r.Value, "card-sha256",
				"no agentCardContent → SVCB has no card-sha256 SvcParam")
		}
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
	assert.Equal(t, "agent-card.json", wkPathFor(ProtocolA2A))
	assert.Equal(t, "mcp.json", wkPathFor(ProtocolMCP))
	assert.Equal(t, "", wkPathFor(ProtocolHTTPAPI),
		"HTTP-API has no per-protocol metadata file convention")
	assert.Equal(t, "", wkPathFor(Protocol("UNKNOWN")))
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
