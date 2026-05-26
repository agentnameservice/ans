package ans

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/godaddy/ans/internal/domain"
)

func TestProtocolToANSValue(t *testing.T) {
	tests := []struct {
		name string
		in   domain.Protocol
		want string
	}{
		{name: "a2a", in: domain.ProtocolA2A, want: "a2a"},
		{name: "mcp", in: domain.ProtocolMCP, want: "mcp"},
		{name: "http_api", in: domain.ProtocolHTTPAPI, want: "http-api"},
		{name: "unknown_protocol_passes_through_unchanged", in: domain.Protocol("UNKNOWN"), want: "UNKNOWN"},
		{name: "empty_protocol_passes_through_as_empty", in: domain.Protocol(""), want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, protocolToANSValue(tc.in))
		})
	}
}

func TestWkPathFor(t *testing.T) {
	tests := []struct {
		name string
		in   domain.Protocol
		want string
	}{
		{name: "a2a_returns_agent_card_json", in: domain.ProtocolA2A, want: "agent-card.json"},
		{name: "mcp_returns_mcp_json", in: domain.ProtocolMCP, want: "mcp.json"},
		{name: "http_api_returns_empty", in: domain.ProtocolHTTPAPI, want: ""},
		{name: "unknown_protocol_returns_empty", in: domain.Protocol("UNKNOWN"), want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wkPathFor(tc.in))
		})
	}
}
