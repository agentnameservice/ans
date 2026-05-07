package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		input   string
		want    Protocol
		wantErr bool
	}{
		{"A2A", ProtocolA2A, false},
		{"a2a", ProtocolA2A, false},
		{"MCP", ProtocolMCP, false},
		{"mcp", ProtocolMCP, false},
		{"HTTP_API", ProtocolHTTPAPI, false},
		{"http-api", ProtocolHTTPAPI, false},
		{"HTTPAPI", ProtocolHTTPAPI, false},
		{"  MCP  ", ProtocolMCP, false},
		{"GRPC", "", true},
		{"", "", true},
		{"unknown", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseProtocol(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProtocol_String(t *testing.T) {
	assert.Equal(t, "MCP", ProtocolMCP.String())
}

func TestProtocol_IsValid(t *testing.T) {
	assert.True(t, ProtocolA2A.IsValid())
	assert.True(t, ProtocolMCP.IsValid())
	assert.True(t, ProtocolHTTPAPI.IsValid())
	assert.False(t, Protocol("").IsValid())
	assert.False(t, Protocol("OTHER").IsValid())
}

func TestParseTransport(t *testing.T) {
	tests := []struct {
		input   string
		want    Transport
		wantErr bool
	}{
		{"STREAMABLE_HTTP", TransportStreamableHTTP, false},
		{"STREAMABLE-HTTP", TransportStreamableHTTP, false},
		{"sse", TransportSSE, false},
		{"json-rpc", TransportJSONRPC, false},
		{"JSONRPC", TransportJSONRPC, false},
		{"GRPC", TransportGRPC, false},
		{"REST", TransportREST, false},
		{"HTTP", TransportHTTP, false},
		{"  SSE  ", TransportSSE, false},
		{"UNKNOWN", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseTransport(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTransport_String_IsValid(t *testing.T) {
	assert.Equal(t, "SSE", TransportSSE.String())
	assert.True(t, TransportSSE.IsValid())
	assert.False(t, Transport("OTHER").IsValid())
}
