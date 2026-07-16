package ans

import (
	"fmt"
	"net/url"

	"github.com/godaddy/ans/internal/domain"
)

// BadgeRecord returns the `_ans-badge.<fqdn>` TXT record every ANS-family
// style emits as the trust attestation hook. Returns a one-element slice
// when reg has at least one endpoint; returns an empty slice otherwise so
// callers can `append(records, BadgeRecord(reg, tlPublicBaseURL)...)`
// unconditionally.
//
// The badge url= points at the Transparency Log's badge endpoint for this
// agent (`<tlPublicBaseURL>/v1/agents/<agentID>`) when tlPublicBaseURL is
// set and the registration carries an AgentID; otherwise it falls back to
// the first endpoint's own URL. Pointing at the TL is the correct target —
// badge verifiers resolve trust through the log, not the agent's host.
//
// Both ANS_DNSAID and ANS_TXT styles call BadgeRecord. When both are in
// the resolved set the service walker dedupes on (Name, Type, Value),
// so the badge lands once per registration regardless of style count.
//
// Required=true: badge-verifying clients won't trust an agent that
// publishes its discovery records without a paired badge — every
// non-badge ANS record on the wire is meaningless without it.
func BadgeRecord(reg *domain.AgentRegistration, tlPublicBaseURL string) []domain.ExpectedDNSRecord {
	if len(reg.Endpoints) == 0 {
		return nil
	}
	// version= carries the v-prefixed ANSName version segment (ANS-3
	// §6.3), matching the leading label of the ANS name — not the bare
	// semver.
	version := reg.AnsName.VersionSegment()
	badgeURL := reg.Endpoints[0].AgentURL
	if tlPublicBaseURL != "" && reg.AgentID != "" {
		// tlPublicBaseURL is validated at config load (https, no
		// query/fragment/userinfo), so JoinPath cannot fail here.
		badgeURL, _ = url.JoinPath(tlPublicBaseURL, "v1", "agents", reg.AgentID)
	}
	value := fmt.Sprintf("v=ans-badge1; version=%s; url=%s",
		version, badgeURL)
	return []domain.ExpectedDNSRecord{{
		Name:     fmt.Sprintf("_ans-badge.%s", reg.FQDN()),
		Type:     domain.DNSRecordTXT,
		Value:    value,
		Purpose:  domain.PurposeBadge,
		Required: true,
		TTL:      3600,
	}}
}
