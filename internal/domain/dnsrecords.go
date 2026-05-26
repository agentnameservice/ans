package domain

// DNSRecordStyle names one DNS record family the RA can emit for an
// agent registration. A registration carries a *set* of styles
// (AgentRegistration.DNSRecordStyles); operators publishing the union
// during a Consolidated Approach transition include both ANS_SVCB and
// ANS_TXT in the same set.
//
// Wire values are CONSTANT_CASE, matching every other enum on the V2
// register schema (Protocol, RevocationReason, AgentLifecycleStatus,
// NextStep.action, ChallengeInfo.type, DnsRecord.type, etc.). The
// `ANS_` prefix anchors the namespace so a future second agentic spec
// adding its own SVCB family doesn't collide.
type DNSRecordStyle string

const (
	// DNSRecordStyleSVCB emits Consolidated Approach SVCB records per
	// RFC 9460 — one row per protocol at the bare FQDN, carrying alpn,
	// port, wk, and card-sha256 SvcParams.
	DNSRecordStyleSVCB DNSRecordStyle = "ANS_SVCB"

	// DNSRecordStyleTXT emits the original `_ans` TXT shape — one row
	// per protocol at `_ans.{fqdn}`. Supported indefinitely for
	// operators with existing zone-edit tooling that targets `_ans.`.
	// Includes an HTTPS RR at the bare FQDN since `_ans` TXT carries
	// no connection hints.
	DNSRecordStyleTXT DNSRecordStyle = "ANS_TXT"
)

// DefaultDNSRecordStyles is the set applied when the registration
// request omits dnsRecordStyles entirely. Pinned to {ANS_SVCB} so new
// integrations follow §4.4.2's "publish one SVCB record... rather than
// parallel per-ecosystem record trees" SHOULD by default. Returned as a
// fresh slice so callers can mutate without affecting the canonical set.
func DefaultDNSRecordStyles() []DNSRecordStyle {
	return []DNSRecordStyle{DNSRecordStyleSVCB}
}

// IsValid reports whether s is one of the defined styles. Empty
// string is treated as invalid; callers normalize empty/missing
// dnsRecordStyles to DefaultDNSRecordStyles() before validation.
//
// Coherence with the discovery registry is enforced at server start:
// cmd/ans-ra/main.go asserts that every style in
// ValidDNSRecordStyles() has a registered port.DiscoveryStyle adapter
// and vice versa. Drift fails server start, not the first verify-dns
// call.
func (s DNSRecordStyle) IsValid() bool {
	switch s {
	case DNSRecordStyleSVCB, DNSRecordStyleTXT:
		return true
	}
	return false
}

// ValidDNSRecordStyles returns the canonical valid set as strings —
// the single source of truth for enum membership. Used by error
// messages and spec generation tooling so adding a third style is a
// one-place change rather than a shotgun edit.
func ValidDNSRecordStyles() []string {
	return []string{
		string(DNSRecordStyleSVCB),
		string(DNSRecordStyleTXT),
	}
}

// DNSRecordType represents a DNS record type.
type DNSRecordType string

const (
	DNSRecordTXT   DNSRecordType = "TXT"
	DNSRecordTLSA  DNSRecordType = "TLSA"
	DNSRecordHTTPS DNSRecordType = "HTTPS"
	// DNSRecordSVCB is the "Consolidated Approach" service binding
	// record (RFC 9460) emitted at the agent's bare FQDN. One SVCB
	// record per protocol carries that protocol's connection hints and
	// capability locators in a single DNS lookup. SvcParams from
	// sibling families coexist in the same record per RFC 9460 §8
	// unknown-key ignore semantics.
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
