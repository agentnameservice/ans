package domain

import (
	"fmt"
	"strings"
)

// Protocol represents the communication protocol an agent endpoint supports.
type Protocol string

const (
	ProtocolA2A     Protocol = "A2A"
	ProtocolMCP     Protocol = "MCP"
	ProtocolHTTPAPI Protocol = "HTTP_API"
)

// ParseProtocol parses a protocol string (case-insensitive).
func ParseProtocol(s string) (Protocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "A2A":
		return ProtocolA2A, nil
	case "MCP":
		return ProtocolMCP, nil
	case "HTTP_API", "HTTP-API", "HTTPAPI":
		return ProtocolHTTPAPI, nil
	default:
		return "", NewValidationError(
			"INVALID_PROTOCOL",
			fmt.Sprintf("unsupported protocol: %q (valid: A2A, MCP, HTTP_API)", s),
		)
	}
}

// String returns the protocol as a string.
func (p Protocol) String() string { return string(p) }

// IsValid returns true if the protocol is a recognized value.
func (p Protocol) IsValid() bool {
	switch p {
	case ProtocolA2A, ProtocolMCP, ProtocolHTTPAPI:
		return true
	default:
		return false
	}
}

// Transport represents a communication transport mechanism.
type Transport string

const (
	TransportStreamableHTTP Transport = "STREAMABLE_HTTP"
	TransportSSE            Transport = "SSE"
	TransportJSONRPC        Transport = "JSON_RPC"
	TransportGRPC           Transport = "GRPC"
	TransportREST           Transport = "REST"
	TransportHTTP           Transport = "HTTP"
)

// ParseTransport parses a transport string (case-insensitive).
func ParseTransport(s string) (Transport, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
	switch normalized {
	case "STREAMABLE_HTTP":
		return TransportStreamableHTTP, nil
	case "SSE":
		return TransportSSE, nil
	case "JSON_RPC", "JSONRPC":
		return TransportJSONRPC, nil
	case "GRPC":
		return TransportGRPC, nil
	case "REST":
		return TransportREST, nil
	case "HTTP":
		return TransportHTTP, nil
	default:
		return "", NewValidationError(
			"INVALID_TRANSPORT",
			fmt.Sprintf("unsupported transport: %q", s),
		)
	}
}

// String returns the transport as a string.
func (t Transport) String() string { return string(t) }

// IsValid returns true if the transport is a recognized value.
func (t Transport) IsValid() bool {
	switch t {
	case TransportStreamableHTTP, TransportSSE, TransportJSONRPC,
		TransportGRPC, TransportREST, TransportHTTP:
		return true
	default:
		return false
	}
}
