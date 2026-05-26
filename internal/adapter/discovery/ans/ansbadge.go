package ans

import (
	"fmt"

	"github.com/godaddy/ans/internal/domain"
)

// BadgeRecord returns the `_ans-badge.<fqdn>` TXT record every ANS-family
// style emits as the trust attestation hook. Returns a one-element slice
// when reg has at least one endpoint (the badge value points at the
// first endpoint's URL); returns an empty slice otherwise so callers
// can `append(records, BadgeRecord(reg)...)` unconditionally.
//
// Both ANS_SVCB and ANS_TXT styles call BadgeRecord. When both are in
// the resolved set the service walker dedupes on (Name, Type, Value),
// so the badge lands once per registration regardless of style count.
//
// Required=true: badge-verifying clients won't trust an agent that
// publishes its discovery records without a paired badge — every
// non-badge ANS record on the wire is meaningless without it.
func BadgeRecord(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	if len(reg.Endpoints) == 0 {
		return nil
	}
	version := reg.AnsName.Version().String()
	value := fmt.Sprintf("v=ans-badge1; version=%s; url=%s",
		version, reg.Endpoints[0].AgentURL)
	return []domain.ExpectedDNSRecord{{
		Name:     fmt.Sprintf("_ans-badge.%s", reg.FQDN()),
		Type:     domain.DNSRecordTXT,
		Value:    value,
		Purpose:  domain.PurposeBadge,
		Required: true,
		TTL:      3600,
	}}
}
