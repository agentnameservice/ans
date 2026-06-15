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

	records := ComputeRequiredDNSRecords(reg, "")
	require.NotEmpty(t, records)

	// 2 endpoints → 2 _ans TXT records + 1 badge record.
	var anxCount, badgeCount, tlsaCount int
	for _, r := range records {
		switch r.Purpose {
		case PurposeDiscovery:
			anxCount++
			assert.Equal(t, DNSRecordTXT, r.Type)
			assert.True(t, strings.HasPrefix(r.Name, "_ans."))
			assert.True(t, r.Required)
			assert.Contains(t, r.Value, "v=ans1")
			// Version is bare semver, not DNS-label form — TXT
			// payloads carry the machine-parseable semver directly.
			assert.Contains(t, r.Value, "version=1.2.3")
			assert.NotContains(t, r.Value, "v1.2.3", "no v-prefix in TXT payload")
			assert.NotContains(t, r.Value, "1-2-3", "no dash form anywhere")
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

	assert.Equal(t, 2, anxCount)
	assert.Equal(t, 1, badgeCount)
	assert.Equal(t, 0, tlsaCount, "no cert → no TLSA record")
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

	records := ComputeRequiredDNSRecords(reg, "")

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
	records := ComputeRequiredDNSRecords(reg, "")
	assert.Empty(t, records)
}

func TestComputeRequiredDNSRecords_BadgeURLPointsToTL(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AgentID: "test-agent-id",
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
		},
	}

	records := ComputeRequiredDNSRecords(reg, "https://tl.example.org")
	for _, r := range records {
		if r.Purpose == PurposeBadge {
			assert.Contains(t, r.Value, "url=https://tl.example.org/v1/agents/test-agent-id")
			assert.NotContains(t, r.Value, "agent.example.com/mcp")
			return
		}
	}
	t.Fatal("no badge record found")
}

func TestComputeRequiredDNSRecords_BadgeFallbackWithoutTLURL(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
		},
	}

	records := ComputeRequiredDNSRecords(reg, "")
	for _, r := range records {
		if r.Purpose == PurposeBadge {
			assert.Contains(t, r.Value, "url=https://agent.example.com/mcp")
			return
		}
	}
	t.Fatal("no badge record found")
}

func TestComputeRequiredDNSRecords_SVCBFromEndpoint(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolA2A, AgentURL: "https://real-host.example.com:8080/a2a"},
		},
	}

	records := ComputeRequiredDNSRecords(reg, "")
	var svcbFound bool
	for _, r := range records {
		if r.Purpose == PurposeConnectivity {
			svcbFound = true
			assert.Equal(t, DNSRecordSVCB, r.Type)
			assert.Equal(t, "agent.example.com", r.Name)
			assert.Contains(t, r.Value, "real-host.example.com.")
			assert.Contains(t, r.Value, "alpn=h2")
			assert.Contains(t, r.Value, "port=8080")
			assert.True(t, r.Required)
		}
	}
	assert.True(t, svcbFound, "SVCB record should be generated")
}

func TestComputeRequiredDNSRecords_SVCBDefaultPort(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	reg := &AgentRegistration{
		AnsName: ansName,
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://real-host.example.com/mcp"},
		},
	}

	records := ComputeRequiredDNSRecords(reg, "")
	for _, r := range records {
		if r.Purpose == PurposeConnectivity {
			assert.Contains(t, r.Value, "real-host.example.com.")
			assert.Contains(t, r.Value, "alpn=h2")
			assert.NotContains(t, r.Value, "port=", "default port 443 should be omitted")
			return
		}
	}
	t.Fatal("no SVCB record found")
}

func TestBuildSVCBValue(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://host.example.com/a2a", "1 host.example.com. alpn=h2"},
		{"https://host.example.com:8080/mcp", "1 host.example.com. alpn=h2 port=8080"},
		{"http://host.example.com:9000/api", "1 host.example.com. alpn=http/1.1 port=9000"},
		{"https://host.example.com:443/default", "1 host.example.com. alpn=h2"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, buildSVCBValue(tc.url), "url=%s", tc.url)
	}
}

func TestProtocolToANSValue(t *testing.T) {
	assert.Equal(t, "a2a", protocolToANSValue(ProtocolA2A))
	assert.Equal(t, "mcp", protocolToANSValue(ProtocolMCP))
	assert.Equal(t, "http-api", protocolToANSValue(ProtocolHTTPAPI))
	assert.Equal(t, "UNKNOWN", protocolToANSValue(Protocol("UNKNOWN")))
}
