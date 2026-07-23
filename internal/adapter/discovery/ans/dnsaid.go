package ans

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// DNSAIDProfile implements port.ProfileEmitter for the DNS-AID-aligned
// SVCB shape (ANS_DNSAID). It emits one SVCB row per protocol endpoint at
// the agent's bare FQDN, plus the ANS-family trust records (`_ans-badge`
// TXT and TLSA) so the profile is self-contained when registered alone.
//
// Records always returns SVCB rows with Required=true. The service walker
// post-processes the slice to flip Required=false on these rows when
// ANS_TXT is also in the resolved set (during the §4.4.2 transition the
// legacy `_ans` TXT family carries the operator's required signal and
// SVCB rides along as optional). Keeping the post-process at the service
// layer keeps DNSAIDProfile profile-local — it does not need to know
// which other profiles are in play.
//
// SvcParam composition per RFC 9460, written in ascending key order:
//   - alpn: protocol token (a2a / mcp / x-http), distinguishes protocols
//     within the same RRset. From protocolToDNSAIDValue.
//   - port: from endpoint URL authority; defaults to 443 (https) /
//     80 (http) when the URL omits a port.
//   - key65400 (cap): the operator's metadata descriptor URL
//     (AgentEndpoint.MetadataURL) — the exact document key65401 digests.
//     Emitted only when the endpoint supplies a metadataUrl. DNS-AID
//     draft-02 param `cap`.
//   - key65401 (cap-sha256): base64url(raw SHA-256 bytes) of the metadata
//     document, sourced from this endpoint's MetadataHash. Absent when
//     MetadataHash is empty or malformed. DNS-AID draft-02 `cap-sha256`.
//   - key65402 (bap): the agent protocol, emitted on every row. It
//     currently equals alpn (alpn doubles as transport and protocol when
//     a single protocol is supported), but DNS-AID consumers read bap as
//     the authoritative agent-protocol field, so it is always present.
//     DNS-AID draft-02 `bap`.
//   - key65409 (well-known): the RFC 8615 suffix, derived from the
//     metadataUrl path (wellKnownSuffixFromMetadataURL) only when the
//     metadataUrl sits at `https://{FQDN}/.well-known/<suffix>`. DNS-AID
//     draft-02 `well-known`.
//
// Private Use SvcParamKeys (RFC 9460 §14.3.1). The DNS-AID draft's named
// params (cap / cap-sha256 / bap / well-known) have no IANA-assigned code
// point, so they MUST be emitted in the keyNNNNN presentation form (RFC
// 9460 §2.1) — the named forms are unparseable: miekg/dns (and therefore
// ans-dns) and real DNS providers reject `cap=`/`bap=` with "bad SVCB
// key", and the lookup verifier can only ever observe live records in
// keyNNNNN form. key65400–key65409 sit in the §14.3.1 Private Use range
// (65280–65534) and match DNS-AID draft-02 §4's IANA-Considerations
// assignments.
//
// Caveats of the Private Use range:
//   - Collision with another experiment that picks the same code points
//     is intrinsic to Private Use, but it is bounded to
//     denial-of-verification: the verifier's subset matcher requires
//     equal values, so a colliding key with a different value can only
//     cause a false negative (verify-dns fails), never a false accept.
//   - If these params are IANA-registered later, switching the
//     presentation form back to named keys is a real operator-facing
//     migration (the published record value changes), not a silent swap.
//
// Deliberately NOT emitted (see the package design notes):
//   - mandatory=: emitting `mandatory=key65400` would make the whole
//     record invisible to every generic RFC 9460 client that doesn't
//     understand the key, defeating the §8 coexistence goal.
//   - ipv4hint/ipv6hint: the RA knows endpoint URLs, not addresses;
//     registry-sourced address hints go stale and are out of scope.
type DNSAIDProfile struct {
	// tlPublicBaseURL feeds the family `_ans-badge` url= via BadgeRecord
	// (empty falls the badge back to the agent's own endpoint URL). Set
	// once by NewDNSAIDProfile; profiles are immutable after wiring, so
	// Records stays a pure function of reg.
	tlPublicBaseURL string
}

// RFC 9460 §14.3.1 Private Use SvcParamKeys for the DNS-AID draft-02
// params, which have no IANA code point. Emitted in keyNNNNN presentation
// form because the named forms (`cap`, `cap-sha256`, `bap`, `well-known`)
// are rejected by miekg/dns and real DNS providers (see DNSAIDProfile
// doc). The numbers match DNS-AID draft-02 §4.
const (
	// svcbKeyCap carries the capability locator URI (draft `cap`).
	svcbKeyCap = "key65400"
	// svcbKeyCapSHA256 carries the base64url SHA-256 capability digest of
	// the endpoint metadata document (draft `cap-sha256`).
	svcbKeyCapSHA256 = "key65401"
	// svcbKeyBAP carries the agent protocol (draft `bap`).
	svcbKeyBAP = "key65402"
	// svcbKeyWellKnown carries the RFC 8615 well-known suffix (draft
	// `well-known`).
	svcbKeyWellKnown = "key65409"
)

// schemeHTTP is the plaintext-HTTP URL scheme, used for the port-default
// and plaintext-endpoint checks. (The DNSAID HTTP-API protocol token is
// "x-http", a distinct value — see protocolToDNSAIDValue.)
const schemeHTTP = "http"

// NewDNSAIDProfile builds an ANS_DNSAID profile whose family `_ans-badge`
// record points at the transparency log at tlPublicBaseURL. Empty
// tlPublicBaseURL falls the badge back to the agent's own endpoint URL.
func NewDNSAIDProfile(tlPublicBaseURL string) DNSAIDProfile {
	return DNSAIDProfile{tlPublicBaseURL: tlPublicBaseURL}
}

// ID returns ANS_DNSAID.
func (DNSAIDProfile) ID() domain.DiscoveryProfile { return domain.DiscoveryProfileANSDNSAID }

// Records returns the SVCB rows + family trust records the DNSAID profile
// needs an operator to publish.
func (s DNSAIDProfile) Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	fqdn := reg.FQDN()
	// Capacity: N SVCB rows + badge + up to N TLSA (one per distinct TLS
	// port, see TLSARecord/Fix B).
	records := make([]domain.ExpectedDNSRecord, 0, 2*len(reg.Endpoints)+1)
	for _, ep := range reg.Endpoints {
		alpn := protocolToDNSAIDValue(ep.Protocol)
		port := svcbPortFor(ep.AgentURL)
		capSHA := metadataHashToCapSHA256(ep.MetadataHash)
		// RFC 9460 §2.1 presentation form, unquoted: alpn tokens, port
		// digits, the metadataUrl (validated presentation-safe by
		// domain.validateMetadataURL — no whitespace/quote/escape bytes),
		// and base64url digests all render verbatim through the miekg/dns
		// serve path and the lookup verifier's parse. key65400–key65409
		// are the §14.3.1 Private Use presentation of the DNS-AID draft-02
		// params (named forms are unparseable — see DNSAIDProfile doc).
		value := fmt.Sprintf(`1 . alpn=%s port=%d`, alpn, port)
		if ep.MetadataURL != "" {
			value += fmt.Sprintf(` %s=%s`, svcbKeyCap, ep.MetadataURL)
		}
		if capSHA != "" {
			value += fmt.Sprintf(` %s=%s`, svcbKeyCapSHA256, capSHA)
		}
		// bap is emitted on every row; it currently equals alpn but is the
		// authoritative agent-protocol field for DNS-AID consumers.
		value += fmt.Sprintf(` %s=%s`, svcbKeyBAP, alpn)
		if wk := wellKnownSuffixFromMetadataURL(ep.MetadataURL, fqdn); wk != "" {
			value += fmt.Sprintf(` %s=%s`, svcbKeyWellKnown, wk)
		}
		records = append(records, domain.ExpectedDNSRecord{
			Name:     fqdn,
			Type:     domain.DNSRecordSVCB,
			Value:    value,
			Purpose:  domain.PurposeDiscovery,
			Required: true,
			TTL:      3600,
		})
	}
	records = append(records, BadgeRecord(reg, s.tlPublicBaseURL)...)
	records = append(records, TLSARecord(reg)...)
	return records
}

// Compile-time interface satisfaction check. Catches accidental
// signature drift on port.ProfileEmitter without needing a runtime
// assertion in cmd/main.
var _ port.ProfileEmitter = DNSAIDProfile{}

// svcbPortFor returns the TCP port to advertise in the SVCB SvcParam
// `port=`. Reads it from the endpoint URL's authority. Falls back to
// 443 (https) / 80 (http) when the URL omits a port. Empty input or
// unparseable URL returns 443 — the §4.4.2 default for agent endpoints.
//
// Without this, every endpoint would emit a hardcoded port=443 and
// silently break verify-dns for agents on non-443 endpoints (operator
// publishes their actual port; expected says 443; mismatch).
func svcbPortFor(agentURL string) int {
	if agentURL == "" {
		return 443
	}
	u, err := url.Parse(agentURL)
	if err != nil {
		return 443
	}
	if p := u.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr == nil {
			return n
		}
	}
	if u.Scheme == schemeHTTP {
		return 80
	}
	return 443
}

// metadataHashToCapSHA256 converts an AgentEndpoint.MetadataHash
// (`SHA256:<64-hex-chars>`) into the base64url form (RFC 4648 §5,
// no padding) the SVCB capability-digest SvcParam (key65401, draft
// `cap-sha256`) expects. Empty input, missing prefix, malformed hex,
// or a digest that isn't exactly 32 bytes all return the empty
// string, which the caller treats as "omit the SvcParam entirely".
// The domain layer (endpoint.go's metadataHashPattern) validates the
// canonical shape on input, so the defensive returns here exist for
// boundary safety only — the length check makes this function's
// defensiveness match the SHA-256 contract it documents rather than
// relying solely on the upstream regex.
func metadataHashToCapSHA256(metadataHash string) string {
	if metadataHash == "" {
		return ""
	}
	const prefix = "SHA256:"
	if !strings.HasPrefix(metadataHash, prefix) {
		return ""
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(metadataHash, prefix))
	if err != nil || len(raw) != sha256.Size {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
