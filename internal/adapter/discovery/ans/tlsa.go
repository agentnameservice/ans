package ans

import (
	"fmt"

	"github.com/godaddy/ans/internal/domain"
)

// TLSARecord returns the TLSA cert-binding record every ANS-family
// style emits for the agent's server cert. Returns a one-element slice
// when reg.ServerCert is set; returns an empty slice otherwise.
//
// Both ANS_SVCB and ANS_TXT styles call TLSARecord. When both are in
// the resolved set the service walker dedupes on (Name, Type, Value)
// so the TLSA lands once.
//
// Required=false: TLSA is only meaningful when the operator's zone is
// DNSSEC-signed, which is a runtime property the domain layer cannot
// know. The verify layer enforces a stricter rule at query time: when
// a TLSA response IS DNSSEC-validated, its value MUST match the
// expected fingerprint (otherwise an attacker rewrote the record in
// a signed zone — the worst failure mode). That post-verify check
// lives alongside the verifier (lifecycle.go), not in the record set.
//
// `3 1 1 <hex>` = DANE-EE + SubjectPublicKeyInfo + SHA-256 (RFC 6698).
func TLSARecord(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	if reg.ServerCert == nil {
		return nil
	}
	return []domain.ExpectedDNSRecord{{
		Name:     fmt.Sprintf("_443._tcp.%s", reg.FQDN()),
		Type:     domain.DNSRecordTLSA,
		Value:    fmt.Sprintf("3 1 1 %s", reg.ServerCert.Fingerprint),
		Purpose:  domain.PurposeCertificateBinding,
		Required: false,
		TTL:      3600,
	}}
}
