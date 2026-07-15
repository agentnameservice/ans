package ans

import (
	"fmt"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// TXTProfile implements port.ProfileEmitter for the original `_ans` TXT
// shape (ANS_TXT). It emits one TXT row per protocol endpoint at
// `_ans.<fqdn>` plus an HTTPS RR at the bare FQDN (when at least one
// endpoint is present), plus the ANS-family trust records.
//
// Behavior change vs. the pre-refactor domain function: the HTTPS RR
// is now gated on `len(reg.Endpoints) > 0`. The pre-refactor code
// emitted an HTTPS RR unconditionally inside the `if emitTXT` branch,
// producing a degenerate `[HTTPS-RR-only]` record set when an
// operator selected ANS_TXT with zero endpoints — a service binding
// for a non-existent agent. The refactor folds this fix in; the PR
// description calls it out.
//
// The HTTPS RR carries `1 . alpn=h2` — service binding for HTTP/2.
// Required=false because operators on CNAME-fronted apex zones cannot
// publish this record at the same name (CNAME at @ blocks HTTPS RR
// per RFC 1034 §3.6.2); the spec does not block them on its absence.
type TXTProfile struct {
	// tlPublicBaseURL feeds the family `_ans-badge` url= via BadgeRecord
	// (empty falls the badge back to the agent's own endpoint URL). Set
	// once by NewTXTProfile; profiles are immutable after wiring, so Records
	// stays a pure function of reg.
	tlPublicBaseURL string
}

// NewTXTProfile builds an ANS_TXT profile whose family `_ans-badge` record
// points at the transparency log at tlPublicBaseURL. Empty tlPublicBaseURL
// falls the badge back to the agent's own endpoint URL.
func NewTXTProfile(tlPublicBaseURL string) TXTProfile {
	return TXTProfile{tlPublicBaseURL: tlPublicBaseURL}
}

// ID returns ANS_TXT.
func (TXTProfile) ID() domain.DiscoveryProfile { return domain.DiscoveryProfileANSTXT }

// Records returns the `_ans` TXT rows (one per endpoint) plus the
// HTTPS RR (when at least one endpoint exists) plus the family trust
// records.
func (s TXTProfile) Records(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	fqdn := reg.FQDN()
	// version= carries the v-prefixed ANSName version segment (ANS-3
	// §6.3, ans-txt profile §2), matching the leading label of the ANS
	// name — not the bare semver.
	version := reg.AnsName.VersionSegment()
	var records []domain.ExpectedDNSRecord
	for _, ep := range reg.Endpoints {
		value := fmt.Sprintf("v=ans1; version=%s; p=%s; mode=direct; url=%s",
			version, protocolToANSValue(ep.Protocol), ep.AgentURL)
		records = append(records, domain.ExpectedDNSRecord{
			Name:     fmt.Sprintf("_ans.%s", fqdn),
			Type:     domain.DNSRecordTXT,
			Value:    value,
			Purpose:  domain.PurposeDiscovery,
			Required: true,
			TTL:      3600,
		})
	}
	if len(reg.Endpoints) > 0 {
		records = append(records, domain.ExpectedDNSRecord{
			Name:     fqdn,
			Type:     domain.DNSRecordHTTPS,
			Value:    `1 . alpn=h2`,
			Purpose:  domain.PurposeDiscovery,
			Required: false,
			TTL:      3600,
		})
	}
	records = append(records, BadgeRecord(reg, s.tlPublicBaseURL)...)
	records = append(records, TLSARecord(reg)...)
	return records
}

var _ port.ProfileEmitter = TXTProfile{}
