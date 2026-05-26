package ans

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// SVCBStyle implements port.DiscoveryStyle for the Consolidated
// Approach SVCB shape (ANS_SVCB). It emits one SVCB row per protocol
// endpoint at the agent's bare FQDN, plus the ANS-family trust
// records (`_ans-badge` TXT and TLSA) so the style is self-contained
// when registered alone.
//
// Records always returns SVCB rows with Required=true. The service
// walker post-processes the slice to flip Required=false on these
// rows when ANS_TXT is also in the resolved set (during the §4.4.2
// transition the legacy `_ans` TXT family carries the operator's
// required signal and SVCB rides along as optional). Keeping the
// post-process at the service layer keeps SVCBStyle style-local —
// it does not need to know which other styles are in play.
//
// SvcParam composition per RFC 9460:
//   - alpn: protocol token (a2a / mcp / http-api), distinguishes
//     protocols within the same RRset.
//   - port: from endpoint URL authority; defaults to 443 (https) /
//     80 (http) when the URL omits a port.
//   - wk: well-known suffix per protocol (agent-card.json for A2A,
//     mcp.json for MCP, omitted for HTTP-API).
//   - card-sha256: base64url(raw SHA-256 bytes) sourced from this
//     endpoint's MetadataHash when the operator submitted one.
//     Absent when MetadataHash is empty or malformed; in that case
//     verifiers fetch the metadata document and accept any payload
//     whose URL matches.
//
// `wk` and `card-sha256` are not yet IANA-registered SvcParamKeys;
// see the consolidated-draft §6 note for the keyNNNNN-form fallback
// strict-RFC parsers may need.
type SVCBStyle struct{}

// ID returns ANS_SVCB.
func (SVCBStyle) ID() domain.DNSRecordStyle { return domain.DNSRecordStyleSVCB }

// Records returns the SVCB rows + family trust records the SVCB style
// needs an operator to publish.
func (s SVCBStyle) Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	fqdn := reg.FQDN()
	records := make([]domain.ExpectedDNSRecord, 0, len(reg.Endpoints)+2)
	for _, ep := range reg.Endpoints {
		alpn := protocolToANSValue(ep.Protocol)
		wk := wkPathFor(ep.Protocol)
		port := svcbPortFor(ep.AgentURL)
		cardSHA := metadataHashToCardSHA256(ep.MetadataHash)
		// RFC 9460 §2.1 presentation form: unquoted SvcParamValue when the
		// value has no characters special to the presentation format.
		// alpn tokens, port digits, well-known path suffixes, and
		// base64url digests all qualify.
		value := fmt.Sprintf(`1 . alpn=%s port=%d`, alpn, port)
		if wk != "" {
			value += fmt.Sprintf(` wk=%s`, wk)
		}
		if cardSHA != "" {
			value += fmt.Sprintf(` card-sha256=%s`, cardSHA)
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
	records = append(records, BadgeRecord(reg)...)
	records = append(records, TLSARecord(reg)...)
	return records
}

// Compile-time interface satisfaction check. Catches accidental
// signature drift on port.DiscoveryStyle without needing a runtime
// assertion in cmd/main.
var _ port.DiscoveryStyle = SVCBStyle{}

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

// metadataHashToCardSHA256 converts an AgentEndpoint.MetadataHash
// (`SHA256:<64-hex-chars>`) into the base64url form (RFC 4648 §5,
// no padding) the SVCB `card-sha256` SvcParam expects. Empty input,
// missing prefix, or malformed hex all return the empty string,
// which the caller treats as "omit the SvcParam entirely". The
// domain layer (endpoint.go's metadataHashPattern) validates the
// canonical shape on input, so the defensive returns here exist
// for boundary safety only.
func metadataHashToCardSHA256(metadataHash string) string {
	if metadataHash == "" {
		return ""
	}
	const prefix = "SHA256:"
	if !strings.HasPrefix(metadataHash, prefix) {
		return ""
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(metadataHash, prefix))
	if err != nil || len(raw) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
