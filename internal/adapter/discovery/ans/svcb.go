package ans

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// SVCBProfile implements port.ProfileEmitter for the Consolidated
// Approach SVCB shape (ANS_SVCB). It emits one SVCB row per protocol
// endpoint at the agent's bare FQDN, plus the ANS-family trust
// records (`_ans-badge` TXT and TLSA) so the profile is self-contained
// when registered alone.
//
// Records always returns SVCB rows with Required=true. The service
// walker post-processes the slice to flip Required=false on these
// rows when ANS_TXT is also in the resolved set (during the §4.4.2
// transition the legacy `_ans` TXT family carries the operator's
// required signal and SVCB rides along as optional). Keeping the
// post-process at the service layer keeps SVCBProfile profile-local —
// it does not need to know which other profiles are in play.
//
// SvcParam composition per RFC 9460:
//   - alpn: protocol token (a2a / mcp / http-api), distinguishes
//     protocols within the same RRset.
//   - port: from endpoint URL authority; defaults to 443 (https) /
//     80 (http) when the URL omits a port.
//   - key65280 (well-known suffix): per-protocol metadata file suffix
//     (agent-card.json for A2A, mcp.json for MCP, omitted for
//     HTTP-API). The DNS-AID draft names this param `wk`.
//   - key65281 (capability digest): base64url(raw SHA-256 bytes)
//     sourced from this endpoint's MetadataHash when the operator
//     submitted one. Absent when MetadataHash is empty or malformed;
//     in that case verifiers fetch the metadata document and accept
//     any payload whose URL matches. The DNS-AID draft names this
//     param `cap-sha256`.
//
// Private Use SvcParamKeys (RFC 9460 §14.3.1). The draft's `wk` and
// `cap-sha256` have no IANA-assigned code point, so they MUST be
// emitted in the keyNNNNN presentation form (RFC 9460 §2.1) — the
// named forms are unparseable: miekg/dns (and therefore ans-dns) and
// real DNS providers reject `wk=`/`cap-sha256=` with "bad SVCB key",
// and the lookup verifier can only ever observe live records in
// keyNNNNN form. key65280 / key65281 sit in the §14.3.1 Private Use
// range (65280–65534).
//
// Caveats of squatting Private Use space:
//   - The DNS-AID draft's own examples squat unassigned space
//     (key65001) — we deliberately do not copy that point; 65280+ is
//     the registered-as-private range, not merely unassigned.
//   - Collision with another experiment that picks the same code
//     points is intrinsic to Private Use, but it is bounded to
//     denial-of-verification: the verifier's subset matcher requires
//     equal values, so a colliding key with a different value can
//     only cause a false negative (verify-dns fails), never a false
//     accept.
//   - If `wk`/`cap-sha256` are IANA-registered later, switching the
//     presentation form back to named keys is a real operator-facing
//     migration (the published record value changes), not a silent
//     swap.
//
// Deliberately NOT emitted (see the package design notes):
//   - mandatory=: emitting `mandatory=key65280` would make the whole
//     record invisible to every generic RFC 9460 client that doesn't
//     understand the key, defeating the §8 coexistence goal. The
//     draft text that gates client behavior on these params is an
//     upstream DNS-AID tension, not a reason to fence off the record.
//   - ipv4hint/ipv6hint: the RA knows endpoint URLs, not addresses;
//     registry-sourced address hints go stale and are out of scope.
type SVCBProfile struct {
	// tlPublicBaseURL feeds the family `_ans-badge` url= via BadgeRecord
	// (empty falls the badge back to the agent's own endpoint URL). Set
	// once by NewSVCBProfile; profiles are immutable after wiring, so Records
	// stays a pure function of reg.
	tlPublicBaseURL string
}

// RFC 9460 §14.3.1 Private Use SvcParamKeys for the DNS-AID draft
// params that have no IANA code point. Emitted in keyNNNNN
// presentation form because the named forms (`wk`, `cap-sha256`) are
// rejected by miekg/dns and real DNS providers (see SVCBProfile doc).
const (
	// svcbKeyWellKnown carries the per-protocol well-known suffix
	// (draft param `wk`).
	svcbKeyWellKnown = "key65280"
	// svcbKeyCapSHA256 carries the base64url SHA-256 capability digest
	// of the endpoint metadata document (draft param `cap-sha256`).
	svcbKeyCapSHA256 = "key65281"
)

// NewSVCBProfile builds an ANS_SVCB profile whose family `_ans-badge` record
// points at the transparency log at tlPublicBaseURL. Empty tlPublicBaseURL
// falls the badge back to the agent's own endpoint URL.
func NewSVCBProfile(tlPublicBaseURL string) SVCBProfile {
	return SVCBProfile{tlPublicBaseURL: tlPublicBaseURL}
}

// ID returns ANS_SVCB.
func (SVCBProfile) ID() domain.DiscoveryProfile { return domain.DiscoveryProfileANSSVCB }

// Records returns the SVCB rows + family trust records the SVCB profile
// needs an operator to publish.
func (s SVCBProfile) Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	fqdn := reg.FQDN()
	// Capacity: N SVCB rows + badge + up to N TLSA (one per distinct TLS
	// port, see TLSARecord/Fix B).
	records := make([]domain.ExpectedDNSRecord, 0, 2*len(reg.Endpoints)+1)
	for _, ep := range reg.Endpoints {
		alpn := protocolToANSValue(ep.Protocol)
		wk := wkPathFor(ep.Protocol)
		port := svcbPortFor(ep.AgentURL)
		capSHA := metadataHashToCapSHA256(ep.MetadataHash)
		// RFC 9460 §2.1 presentation form: unquoted SvcParamValue when the
		// value has no characters special to the presentation format.
		// alpn tokens, port digits, well-known path suffixes, and
		// base64url digests all qualify. key65280/key65281 are the
		// §14.3.1 Private Use presentation of the draft wk/cap-sha256
		// params (named forms are unparseable — see SVCBProfile doc).
		value := fmt.Sprintf(`1 . alpn=%s port=%d`, alpn, port)
		if wk != "" {
			value += fmt.Sprintf(` %s=%s`, svcbKeyWellKnown, wk)
		}
		if capSHA != "" {
			value += fmt.Sprintf(` %s=%s`, svcbKeyCapSHA256, capSHA)
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
var _ port.ProfileEmitter = SVCBProfile{}

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
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

// metadataHashToCapSHA256 converts an AgentEndpoint.MetadataHash
// (`SHA256:<64-hex-chars>`) into the base64url form (RFC 4648 §5,
// no padding) the SVCB capability-digest SvcParam (key65281, draft
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
