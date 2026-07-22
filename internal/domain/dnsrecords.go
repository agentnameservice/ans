package domain

import "fmt"

// DiscoveryProfile names one DNS record family the RA can emit for an
// agent registration. A registration carries a *set* of profiles
// (AgentRegistration.DiscoveryProfiles); operators publishing the union
// during a Consolidated Approach transition include both ANS_DNSAID and
// ANS_TXT in the same set.
//
// Wire values are CONSTANT_CASE, matching every other enum on the V2
// register schema (Protocol, RevocationReason, AgentLifecycleStatus,
// NextStep.action, ChallengeInfo.type, DnsRecord.type, etc.). The
// `ANS_` prefix anchors the namespace so a future second agentic spec
// adding its own SVCB family doesn't collide.
type DiscoveryProfile string

const (
	// DiscoveryProfileANSDNSAID emits DNS-AID-aligned SVCB records per
	// RFC 9460 — one row per protocol at the bare FQDN, carrying alpn,
	// port, key65402 (bap, the agent protocol), and — when the endpoint
	// supplies them — key65400 (cap, the capability locator from
	// metadataUrl), key65401 (cap-sha256, the capability digest), and
	// key65409 (well-known suffix derived from metadataUrl). These
	// keyNNNNN forms are the RFC 9460 §14.3.1 Private Use presentation of
	// the DNS-AID draft-02 cap/cap-sha256/bap/well-known params, which
	// have no IANA code point; the adapter
	// (internal/adapter/discovery/ans/dnsaid.go) documents why the named
	// forms are unpublishable.
	DiscoveryProfileANSDNSAID DiscoveryProfile = "ANS_DNSAID"

	// DiscoveryProfileANSTXT emits the original `_ans` TXT shape — one row
	// per protocol at `_ans.{fqdn}`. Supported indefinitely for
	// operators with existing zone-edit tooling that targets `_ans.`.
	// Includes an HTTPS RR at the bare FQDN since `_ans` TXT carries
	// no connection hints.
	DiscoveryProfileANSTXT DiscoveryProfile = "ANS_TXT"
)

// DefaultDiscoveryProfiles is the set applied when the registration
// request omits discoveryProfiles entirely. Pinned to {ANS_DNSAID} —
// the DNS-AID-aligned SVCB family is the forward default now that the
// profile is at conformance; operators with zone-edit tooling that
// still targets `_ans.{fqdn}` opt into ANS_TXT explicitly (or publish
// the union during a §4.4.2 transition). The V1 lane is unaffected:
// it never consults this default and stays pinned to ANS_TXT in
// applyDiscoveryProfiles. Returned as a fresh slice so callers can
// mutate without affecting the canonical set.
func DefaultDiscoveryProfiles() []DiscoveryProfile {
	return []DiscoveryProfile{DiscoveryProfileANSDNSAID}
}

// IsValid reports whether s is one of the defined profiles. Empty
// string is treated as invalid; callers normalize empty/missing
// discoveryProfiles to DefaultDiscoveryProfiles() before validation.
//
// Coherence with the discovery registry is enforced at server start:
// cmd/ans-ra/main.go asserts that every profile in
// ValidDiscoveryProfiles() has a registered port.ProfileEmitter adapter
// and vice versa. Drift fails server start, not the first verify-dns
// call.
func (s DiscoveryProfile) IsValid() bool {
	switch s {
	case DiscoveryProfileANSDNSAID, DiscoveryProfileANSTXT:
		return true
	}
	return false
}

// ValidDiscoveryProfiles returns the canonical valid set as strings —
// the single source of truth for enum membership. Used by error
// messages and spec generation tooling so adding a third profile is a
// one-place change rather than a shotgun edit.
func ValidDiscoveryProfiles() []string {
	return []string{
		string(DiscoveryProfileANSDNSAID),
		string(DiscoveryProfileANSTXT),
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

// TLSARecordForCert builds the single DANE-EE TLSA record binding a
// server certificate fingerprint to the FQDN at the default TLS port
// (`_443._tcp.{fqdn}`). It is the server-cert renewal path's analog of
// the registration record set: the renewal status responses surface the
// new leaf's record so the operator can update DNS after a rollover.
//
// The registration record set emits one TLSA per distinct TLS endpoint
// port via the discovery profiles
// (internal/adapter/discovery/ans.TLSARecord); this helper covers the
// single-record renewal-status DTO, which carries the freshly-issued
// leaf's fingerprint rather than reading reg.ServerCert.
//
// `3 0 1 <hex>` = DANE-EE + full-certificate + SHA-256 (RFC 6698).
// Selector 0 (full cert), not 1 (SPKI): the hex is the certificate
// fingerprint — a SHA-256 over the full DER cert (internal/crypto/x509.go
// CertificateFingerprint) — so selector 0 is what matches those bytes.
//
// Required=false: a TLSA record is only trustworthy in a DNSSEC-signed
// zone, which the domain layer cannot know. The verify layer enforces
// the stricter rule at query time: a DNSSEC-validated TLSA response MUST
// match the expected fingerprint.
func TLSARecordForCert(fqdn, fingerprint string) ExpectedDNSRecord {
	return ExpectedDNSRecord{
		Name:     fmt.Sprintf("_443._tcp.%s", fqdn),
		Type:     DNSRecordTLSA,
		Value:    fmt.Sprintf("3 0 1 %s", fingerprint),
		Purpose:  PurposeCertificateBinding,
		Required: false,
		TTL:      3600,
	}
}
