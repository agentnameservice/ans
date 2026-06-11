// Package ans implements the bundled ANS-family port.ProfileEmitter
// adapters: SVCBProfile (the Consolidated Approach SVCB shape per RFC 9460
// plus the `_ans-badge` TXT extension) and TXTProfile (the original `_ans`
// TXT shape, supported indefinitely for operators with existing zone-edit
// tooling). Both profiles share two family-level trust records — the
// `_ans-badge` TXT and the server-cert TLSA — emitted by every ANS-family
// profile and deduped at the service walker.
//
// Helpers private to this package, by file: protocol.go holds the
// protocol-token and well-known-suffix mappings both profiles need;
// svcb.go holds svcbPortFor (consumed by both the SVCB rows and
// tlsa.go's port collection) and the capability-digest (key65281)
// conversion; tlsa.go and ansbadge.go hold the family-level trust
// records (per-port TLSA, `_ans-badge` TXT) every ANS-family profile
// emits.
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
// Consolidated Approach SVCB record's well-known SvcParam (key65280,
// the draft's `wk`). Suffix-only matches the consolidated-draft
// examples (§4 line 134); clients prepend `/.well-known/` to construct
// the full path. Empty result means the caller SHOULD omit the SvcParam
// entirely (e.g. direct-mode agents that expose no canonical metadata
// file).
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
