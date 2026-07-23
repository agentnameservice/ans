package ans

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/agentnameservice/ans/internal/domain"
)

func TestProtocolToANSValue(t *testing.T) {
	tests := []struct {
		name string
		in   domain.Protocol
		want string
	}{
		{name: "a2a", in: domain.ProtocolA2A, want: "a2a"},
		{name: "mcp", in: domain.ProtocolMCP, want: "mcp"},
		// The legacy `_ans` TXT keeps the http-api token; only the DNSAID
		// profile maps HTTP_API to "http" (see TestProtocolToDNSAIDValue).
		{name: "http_api_keeps_legacy_token", in: domain.ProtocolHTTPAPI, want: "http-api"},
		{name: "unknown_protocol_passes_through_unchanged", in: domain.Protocol("UNKNOWN"), want: "UNKNOWN"},
		{name: "empty_protocol_passes_through_as_empty", in: domain.Protocol(""), want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, protocolToANSValue(tc.in))
		})
	}
}

// TestProtocolToDNSAIDValue pins the DNSAID alpn/bap token: identical to
// protocolToANSValue except HTTP_API maps to "http". The a2a/mcp and
// passthrough cases delegate to protocolToANSValue, so the two wire
// families stay aligned on every shared protocol.
func TestProtocolToDNSAIDValue(t *testing.T) {
	tests := []struct {
		name string
		in   domain.Protocol
		want string
	}{
		{name: "a2a_delegates", in: domain.ProtocolA2A, want: "a2a"},
		{name: "mcp_delegates", in: domain.ProtocolMCP, want: "mcp"},
		{name: "http_api_maps_to_x_http", in: domain.ProtocolHTTPAPI, want: "x-http"},
		{name: "unknown_protocol_delegates_passthrough", in: domain.Protocol("UNKNOWN"), want: "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, protocolToDNSAIDValue(tc.in))
		})
	}
}

// TestWellKnownSuffixFromMetadataURL enumerates every reachable branch of
// the metadataUrl→well-known-suffix derivation. The url.Parse error arm
// is SAFETY-annotated unreachable in production (validateMetadataURL has
// already parsed the URL by the time the emitter calls this); the
// malformed-URL case below exercises it directly anyway, and the non-https
// case is its testable companion.
func TestWellKnownSuffixFromMetadataURL(t *testing.T) {
	const fqdn = "agent.example.com"
	tests := []struct {
		name        string
		metadataURL string
		fqdn        string
		want        string
	}{
		{name: "empty_returns_empty", metadataURL: "", fqdn: fqdn, want: ""},
		{name: "canonical_well_known_returns_suffix", metadataURL: "https://agent.example.com/.well-known/mcp.json", fqdn: fqdn, want: "mcp.json"},
		{name: "agent_card_suffix", metadataURL: "https://agent.example.com/.well-known/agent-card.json", fqdn: fqdn, want: "agent-card.json"},
		{name: "explicit_443_port_still_matches_host", metadataURL: "https://agent.example.com:443/.well-known/mcp.json", fqdn: fqdn, want: "mcp.json"},
		{name: "uppercase_host_matches_case_insensitively", metadataURL: "https://AGENT.EXAMPLE.COM/.well-known/mcp.json", fqdn: fqdn, want: "mcp.json"},
		{name: "fqdn_trailing_dot_matches", metadataURL: "https://agent.example.com/.well-known/mcp.json", fqdn: "agent.example.com.", want: "mcp.json"},
		{name: "non_https_returns_empty", metadataURL: "http://agent.example.com/.well-known/mcp.json", fqdn: fqdn, want: ""},
		{name: "host_mismatch_returns_empty", metadataURL: "https://cdn.example.net/.well-known/mcp.json", fqdn: fqdn, want: ""},
		{name: "missing_well_known_prefix_returns_empty", metadataURL: "https://agent.example.com/metadata/mcp.json", fqdn: fqdn, want: ""},
		{name: "empty_suffix_returns_empty", metadataURL: "https://agent.example.com/.well-known/", fqdn: fqdn, want: ""},
		{name: "multi_segment_suffix_returns_empty", metadataURL: "https://agent.example.com/.well-known/sub/mcp.json", fqdn: fqdn, want: ""},
		{name: "malformed_url_returns_empty", metadataURL: "https://agent.example.com/%zz", fqdn: fqdn, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wellKnownSuffixFromMetadataURL(tc.metadataURL, tc.fqdn))
		})
	}
}
