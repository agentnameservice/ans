// Package ans implements the bundled ANS-family port.DiscoveryStyle
// adapters: SVCBStyle (the Consolidated Approach SVCB shape per RFC 9460
// plus the `_ans-badge` TXT extension) and TXTStyle (the original `_ans`
// TXT shape, supported indefinitely for operators with existing zone-edit
// tooling). Both styles share two family-level trust records — the
// `_ans-badge` TXT and the server-cert TLSA — emitted by every ANS-family
// style and deduped at the service walker.
//
// Helpers private to this package handle the per-protocol bits both
// styles need: protocol.go for the human-friendly protocol token and
// well-known suffix mappings, svcb.go for the SVCB-specific port and
// card-sha256 helpers (kept next to their only consumer).
package ans

import (
	"github.com/godaddy/ans/internal/domain"
)

// protocolToANSValue maps a protocol enum to the wire token used inside
// `_ans` TXT payloads (`p=<token>`) and SVCB `alpn=<token>` SvcParams.
// Unknown protocols pass through unchanged so a future protocol added
// to the domain layer surfaces in records without a parallel edit here.
func protocolToANSValue(p domain.Protocol) string {
	switch p {
	case domain.ProtocolA2A:
		return "a2a"
	case domain.ProtocolMCP:
		return "mcp"
	case domain.ProtocolHTTPAPI:
		return "http-api"
	default:
		return string(p)
	}
}

// wkPathFor returns the suffix-only well-known path published in the
// Consolidated Approach SVCB record's `wk=` SvcParam. Suffix-only
// matches the consolidated-draft examples (§4 line 134); clients
// prepend `/.well-known/` to construct the full path. Empty result
// means the caller SHOULD omit `wk=` entirely (e.g. direct-mode agents
// that expose no canonical metadata file).
//
// A2A: `agent-card.json` (IANA-registered well-known per A2A spec).
// MCP:  `mcp.json` (de-facto convention; see SEP-1649 progress).
// HTTP-API: empty (no per-protocol metadata file convention).
func wkPathFor(p domain.Protocol) string {
	switch p {
	case domain.ProtocolA2A:
		return "agent-card.json"
	case domain.ProtocolMCP:
		return "mcp.json"
	default:
		return ""
	}
}
