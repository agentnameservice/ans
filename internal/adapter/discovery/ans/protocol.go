// Package ans implements the bundled ANS-family port.ProfileEmitter
// adapters: DNSAIDProfile (the DNS-AID-aligned SVCB shape per RFC 9460
// plus the `_ans-badge` TXT extension) and TXTProfile (the original `_ans`
// TXT shape, supported indefinitely for operators with existing zone-edit
// tooling). Both profiles share two family-level trust records — the
// `_ans-badge` TXT and the server-cert TLSA — emitted by every ANS-family
// profile and deduped at the service walker.
//
// Helpers private to this package, by file: protocol.go holds the
// protocol-token mappings (protocolToANSValue for the legacy `_ans` TXT
// `p=`, protocolToDNSAIDValue for the DNSAID `alpn=`/`bap=`) and the
// metadataUrl→well-known-suffix derivation; dnsaid.go holds svcbPortFor
// (consumed by both the SVCB rows and tlsa.go's port collection) and the
// capability-digest (key65401) conversion; tlsa.go and ansbadge.go hold
// the family-level trust records (per-port TLSA, `_ans-badge` TXT) every
// ANS-family profile emits.
package ans

import (
	"net/url"
	"strings"

	"github.com/godaddy/ans/internal/domain"
)

// protocolToANSValue maps a protocol enum to the wire token used inside
// the legacy `_ans` TXT payload (`p=<token>`). Unknown protocols pass
// through unchanged so a future protocol added to the domain layer
// surfaces in records without a parallel edit here.
//
// The DNSAID (SVCB) profile uses protocolToDNSAIDValue instead — the two
// wire families share the a2a/mcp tokens but diverge on HTTP_API.
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

// protocolToDNSAIDValue is the token the DNSAID (SVCB) profile emits in
// both the `alpn=` and `bap=` SvcParams. It matches protocolToANSValue
// except HTTP_API maps to "x-http" (DNSAID-only); the legacy `_ans` TXT
// keeps "http-api". The "x-" prefix makes the token a valid DNS-AID
// draft-02 `extension-protocol` for the `bap` SvcParam — a2a / mcp are
// the built-in protocols, everything else MUST be x-prefixed.
//
// NOTE: the delegated default passthrough means a FUTURE non-mcp/a2a
// protocol surfaces here too — such a protocol's token MUST be reviewed
// for DNS-AID alpn-id / extension-protocol conformance (i.e. given an
// "x-" prefix) before it reaches the wire (today only a2a / mcp / x-http
// are emitted).
func protocolToDNSAIDValue(p domain.Protocol) string {
	if p == domain.ProtocolHTTPAPI {
		return "x-http"
	}
	return protocolToANSValue(p)
}

// wellKnownPrefix is the RFC 8615 path prefix — the single source of
// truth for the literal across the package.
const wellKnownPrefix = "/.well-known/"

// wellKnownSuffixFromMetadataURL derives the suffix-only value for the
// DNSAID SVCB `well-known` SvcParam (key65409) from the operator's
// metadataUrl. It returns the single path segment after `/.well-known/`
// only when metadataURL is exactly `https://{fqdn}/.well-known/<suffix>`:
// same scheme (https), same host (port-, case-, and trailing-dot-
// insensitive, matching AgentEndpoint.ValidateHostMatch), and a single
// non-empty trailing segment. Any other shape returns "" (the caller
// omits the SvcParam), so the advertised well-known location is always
// derived from where the metadata document actually lives — never from
// the protocol.
func wellKnownSuffixFromMetadataURL(metadataURL, fqdn string) string {
	if metadataURL == "" {
		return ""
	}
	// SAFETY: the err != nil arm is defensive/unreachable on the
	// production path — endpoint.go's validateURL already parsed this URL
	// successfully before it reaches the emitter. The testable companion
	// guard is the scheme check on the same line.
	u, err := url.Parse(metadataURL)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	if !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(fqdn, ".")) {
		return ""
	}
	if !strings.HasPrefix(u.Path, wellKnownPrefix) {
		return ""
	}
	suffix := strings.TrimPrefix(u.Path, wellKnownPrefix)
	if suffix == "" || strings.Contains(suffix, "/") {
		return "" // single non-empty trailing segment only
	}
	return suffix
}
