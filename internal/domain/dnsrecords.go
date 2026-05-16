package domain

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// DNSRecordStyle selects which DNS record family the RA emits in its
// dnsRecordsProvisioned attestation and in the records it tells the
// operator to publish at registration time.
//
// Default is "consolidated": one SVCB record per protocol at the
// agent's bare FQDN per the cross-draft Consolidated Approach (§4.4.2).
// Operators on infrastructure that already publishes the legacy
// `_ans` TXT family pick "legacy". Migration operators pick "both"
// for a defined window, then flip back to "consolidated".
//
// Legacy MUST stay supported indefinitely. Operators picking "legacy"
// will continue to receive the original `_ans` TXT shape this RA has
// emitted since v0.1.x. The cross-channel hash consistency check
// (§4.4.2) only applies when the SVCB record is present, so "legacy"
// agents do not benefit from the card-sha256 ↔ capabilities_hash
// guarantee — that is a property of the chosen style, not a defect.
type DNSRecordStyle string

const (
	// DNSRecordStyleConsolidated emits Consolidated Approach SVCB
	// records (one per protocol, bare-FQDN owner) plus the
	// `_ans-prefixed` records that no SvcParam covers (badge,
	// identity DANE) plus the server-cert TLSA. The default.
	DNSRecordStyleConsolidated DNSRecordStyle = "consolidated"

	// DNSRecordStyleLegacy emits the original `_ans` TXT family
	// (one per protocol) plus the same `_ans-`-prefixed records
	// plus the server-cert TLSA. No SVCB rows.
	DNSRecordStyleLegacy DNSRecordStyle = "legacy"

	// DNSRecordStyleBoth emits the union of Consolidated Approach
	// SVCB and legacy `_ans` TXT — the transition shape per §4.4.2
	// where the two record families coexist on the same agent's zone.
	DNSRecordStyleBoth DNSRecordStyle = "both"
)

// DefaultDNSRecordStyle is the style applied when the registration
// request omits dnsRecordStyle entirely. Pinned to "consolidated" so
// new integrations follow §4.4.2's "publish one SVCB record... rather
// than parallel per-ecosystem record trees" SHOULD by default.
const DefaultDNSRecordStyle = DNSRecordStyleConsolidated

// IsValid reports whether s is one of the three defined styles.
// Empty string is treated as invalid; callers normalize empty to
// DefaultDNSRecordStyle before validation.
func (s DNSRecordStyle) IsValid() bool {
	switch s {
	case DNSRecordStyleConsolidated, DNSRecordStyleLegacy, DNSRecordStyleBoth:
		return true
	}
	return false
}

// DNSRecordType represents a DNS record type.
type DNSRecordType string

const (
	DNSRecordTXT   DNSRecordType = "TXT"
	DNSRecordTLSA  DNSRecordType = "TLSA"
	DNSRecordHTTPS DNSRecordType = "HTTPS"
	// DNSRecordSVCB is the cross-draft "Consolidated Approach" service
	// binding record (RFC 9460) emitted at the agent's bare FQDN. One
	// SVCB record per protocol carries that protocol's connection hints
	// and capability locators in a single DNS lookup. SvcParams from
	// DNS-AID, ANS, and other agentic specs coexist in the same record
	// per RFC 9460 §8 unknown-key ignore semantics. See ANS_SPEC.md
	// §4.4.2 in github.com/gdcorp-engineering/ans-registry-poc.
	DNSRecordSVCB DNSRecordType = "SVCB"
)

// DNSRecordPurpose describes why a DNS record is needed.
type DNSRecordPurpose string

const (
	PurposeDiscovery          DNSRecordPurpose = "DISCOVERY"
	PurposeTrust              DNSRecordPurpose = "TRUST"
	PurposeCertificateBinding DNSRecordPurpose = "CERTIFICATE_BINDING"
	PurposeBadge              DNSRecordPurpose = "BADGE"
)

// ExpectedDNSRecord represents a DNS record the operator must configure.
type ExpectedDNSRecord struct {
	Name     string           `json:"name"`
	Type     DNSRecordType    `json:"type"`
	Value    string           `json:"value"`
	Purpose  DNSRecordPurpose `json:"purpose"`
	Required bool             `json:"required"`
	TTL      int              `json:"ttl"`
}

// ComputeRequiredDNSRecords generates the DNS records an operator must create
// for a given agent registration. The RA does not create these records — the
// operator manages their own DNS. The RA only verifies they exist.
//
// The set of records emitted depends on reg.DNSRecordStyle:
//
//   - "consolidated" (default, recommended): Consolidated Approach SVCB
//     rows (one per protocol) plus the shared `_ans-`-prefixed records
//     plus the server-cert TLSA. No legacy `_ans` TXT rows.
//   - "legacy": the original `_ans` TXT shape (one row per protocol)
//     plus the same shared records. No SVCB rows. Backwards-compatible
//     with operators who registered before the Consolidated Approach
//     landed and have existing zone-edit tooling for `_ans` TXT.
//   - "both": union of consolidated + legacy. The §4.4.2 transition
//     shape; operators run both record families on the same zone for
//     a defined window, then flip back to "consolidated".
//
// Empty reg.DNSRecordStyle is normalized to DefaultDNSRecordStyle.
func ComputeRequiredDNSRecords(reg *AgentRegistration) []ExpectedDNSRecord {
	fqdn := reg.FQDN()
	// Version is emitted as a bare semver string ("1.2.0"). The
	// `v`-prefixed form only appears inside the ANS name's hostname
	// label — TXT record payloads carry the machine-readable semver
	// directly, matching the shape a client would parse with any
	// semver library.
	version := reg.AnsName.Version().String()
	style := reg.DNSRecordStyle
	if !style.IsValid() {
		style = DefaultDNSRecordStyle
	}
	var records []ExpectedDNSRecord

	emitLegacy := style == DNSRecordStyleLegacy || style == DNSRecordStyleBoth
	emitConsolidated := style == DNSRecordStyleConsolidated || style == DNSRecordStyleBoth

	// _ans TXT record for each protocol endpoint — legacy discovery.
	if emitLegacy {
		for _, ep := range reg.Endpoints {
			value := fmt.Sprintf("v=ans1; version=%s; p=%s; mode=direct; url=%s",
				version, protocolToANSValue(ep.Protocol), ep.AgentURL)
			records = append(records, ExpectedDNSRecord{
				Name:     fmt.Sprintf("_ans.%s", fqdn),
				Type:     DNSRecordTXT,
				Value:    value,
				Purpose:  PurposeDiscovery,
				Required: true,
				TTL:      3600,
			})
		}

		// HTTPS RR (RFC 9460 type 65) at the agent FQDN — service
		// binding for HTTP/2 (and Encrypted Client Hello when the
		// AHP provides an ECH config out-of-band). Per §A.8.1 the
		// RA generates the content; the AHP decides whether to
		// publish based on whether their apex is aliased via CNAME
		// (CNAME at the agent FQDN blocks HTTPS RR at the same name
		// per RFC 1034 §3.6.2).
		//
		// Skipped for the consolidated form: the SVCB rows already
		// carry alpn / port / ECH SvcParams, so an HTTPS RR
		// alongside duplicates content (§A.8.2). Legacy keeps it
		// because the `_ans` TXT family does not carry connection
		// hints — clients without ANS-protocol awareness rely on
		// HTTPS RR for ALPN signalling.
		//
		// Required=false: operators on CNAME-fronted apex zones
		// cannot publish this record at the same name; the spec
		// does not block them on its absence.
		records = append(records, ExpectedDNSRecord{
			Name:     fqdn,
			Type:     DNSRecordHTTPS,
			Value:    `1 . alpn=h2`,
			Purpose:  PurposeDiscovery,
			Required: false,
			TTL:      3600,
		})
	}

	// Consolidated Approach SVCB record at the bare FQDN — one per
	// protocol endpoint. RFC 9460 ServiceMode (SvcPriority 1) with
	// TargetName "." (same name) so address resolution stays at the
	// agent's FQDN. SvcParams from DNS-AID, ANS, and other agentic
	// specs coexist via RFC 9460 §8 unknown-key ignore. card-sha256
	// carries base64url(reg.CapabilitiesHash) when the operator
	// submitted agentCardContent; otherwise the SvcParam is absent
	// and a verifier falls back to TOFU on first Trust Card fetch.
	//
	// Provisional-key note: `wk` and `card-sha256` are not yet
	// IANA-registered SvcParamKeys per RFC 9460 §6. The Consolidated
	// Approach draft emits them by symbolic name; production
	// deployments using strict-RFC parsers MAY need to publish them
	// in keyNNNNN form until registration completes. The expected
	// value the RA writes here uses the symbolic form to match the
	// draft's worked examples; the verifier compares post-
	// normalization, and operators whose authoritative DNS only
	// emits keyNNNNN form will see a mismatch the RA reports as a
	// non-blocking integrity finding (Required=false below).
	//
	// Required=false: §4.4.2 marks the Consolidated Approach as MAY,
	// opt-in alongside the `_ans` TXT family during the transition.
	if emitConsolidated {
		cardSHA := capabilitiesHashBase64URL(reg.CapabilitiesHash)
		for _, ep := range reg.Endpoints {
			alpn := protocolToANSValue(ep.Protocol)
			wk := wkPathFor(ep.Protocol)
			// RFC 9460 §2.1 presentation form: unquoted SvcParamValue when
			// the value has no characters special to the presentation
			// format. alpn tokens (a2a, mcp), port digits, well-known path
			// suffixes (agent-card.json), and base64url digests all qualify.
			// The resolver-side formatter (formatHTTPSValue) also emits
			// unquoted, so the verifier's normalize+compare matches without
			// quote-stripping.
			value := fmt.Sprintf(`1 . alpn=%s port=443`, alpn)
			if wk != "" {
				value += fmt.Sprintf(` wk=%s`, wk)
			}
			if cardSHA != "" {
				value += fmt.Sprintf(` card-sha256=%s`, cardSHA)
			}
			records = append(records, ExpectedDNSRecord{
				Name:     fqdn,
				Type:     DNSRecordSVCB,
				Value:    value,
				Purpose:  PurposeDiscovery,
				Required: false,
				TTL:      3600,
			})
		}
	}

	// _ans-badge TXT record — trust badge. Required alongside _ans:
	// resolvers and badge-verifying clients expect to find both, and
	// publishing _ans without _ans-badge would advertise an agent
	// that fails the public discovery handshake.
	if len(reg.Endpoints) > 0 {
		badgeValue := fmt.Sprintf("v=ans-badge1; version=%s; url=%s",
			version, reg.Endpoints[0].AgentURL)
		records = append(records, ExpectedDNSRecord{
			Name:     fmt.Sprintf("_ans-badge.%s", fqdn),
			Type:     DNSRecordTXT,
			Value:    badgeValue,
			Purpose:  PurposeBadge,
			Required: true,
			TTL:      3600,
		})
	}

	// TLSA record for certificate binding. Every registration has a
	// server cert — either BYOC (operator-submitted) or CSR-signed
	// (RA issues via its configured `ServerCertificateAuthority`).
	// Both paths land through the same ByocServerCertificate struct,
	// so `reg.ServerCert` is set for any registration that's reached
	// verify-dns.
	//
	// `3 1 1 <hex>` = DANE-EE + SubjectPublicKeyInfo + SHA-256
	// (RFC 6698). Required=false: operators whose zones aren't
	// DNSSEC-signed can't produce a trustworthy TLSA record, so the
	// RA doesn't block verify-dns on its presence. The verify layer
	// enforces a stricter rule at query time: when a TLSA response
	// IS DNSSEC-validated, its value must match the expected
	// fingerprint (otherwise an attacker rewrote the record in a
	// signed zone — the worst failure mode). That post-verify
	// check lives alongside the verifier, not in the record set.
	if reg.ServerCert == nil {
		return records
	}
	records = append(records, ExpectedDNSRecord{
		Name:     fmt.Sprintf("_443._tcp.%s", fqdn),
		Type:     DNSRecordTLSA,
		Value:    fmt.Sprintf("3 1 1 %s", reg.ServerCert.Fingerprint),
		Purpose:  PurposeCertificateBinding,
		Required: false,
		TTL:      3600,
	})

	return records
}

func protocolToANSValue(p Protocol) string {
	switch p {
	case ProtocolA2A:
		return "a2a"
	case ProtocolMCP:
		return "mcp"
	case ProtocolHTTPAPI:
		return "http-api"
	default:
		return string(p)
	}
}

// wkPathFor returns the suffix-only well-known path published in the
// Consolidated Approach SVCB record's `wk=` SvcParam. Suffix-only matches
// the consolidated-draft examples (§4 line 134); clients prepend
// `/.well-known/` to construct the full path. Empty result means the
// caller SHOULD omit `wk=` entirely (e.g., direct-mode agents that
// expose no canonical metadata file).
//
// A2A: `agent-card.json` (IANA-registered well-known per A2A spec).
// MCP:  `mcp.json` (de-facto convention; see SEP-1649 progress).
// HTTP-API: empty (no per-protocol metadata file convention).
func wkPathFor(p Protocol) string {
	switch p {
	case ProtocolA2A:
		return "agent-card.json"
	case ProtocolMCP:
		return "mcp.json"
	default:
		return ""
	}
}

// capabilitiesHashBase64URL re-encodes a hex-lowercase SHA-256 digest
// (the form `AgentRegistration.CapabilitiesHash` carries) into the
// base64url form (RFC 4648 §5, no padding) the SVCB `card-sha256`
// SvcParam expects. Empty input returns empty output, which the caller
// SHOULD treat as "omit the SvcParam entirely" — agents registered
// without `agentCardContent` have no committed value to publish.
func capabilitiesHashBase64URL(hexDigest string) string {
	if hexDigest == "" {
		return ""
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil || len(raw) == 0 {
		// Malformed input is logically equivalent to absence; the RA
		// stores well-formed hex by construction (helpers.go:
		// hashAgentCardContent), but defensive on the boundary.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
