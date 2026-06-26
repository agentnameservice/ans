package ans

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/godaddy/ans/internal/domain"
)

// TLSARecord returns the TLSA cert-binding records every ANS-family
// profile emits for the agent's server cert — one record per distinct
// TLS endpoint port. Returns an empty slice when reg.ServerCert is nil.
//
// Both ANS_DNSAID and ANS_TXT profiles call TLSARecord. When both are in
// the resolved set the service walker dedupes on (Name, Type, Value)
// so each TLSA lands once.
//
// Owner name carries the port (RFC 6698): `_<port>._tcp.<fqdn>`. A
// DANE client connecting to a non-443 endpoint (8443 etc.) queries
// `_8443._tcp.` — emitting only `_443._tcp.` strands it. Ports come
// from the endpoint URLs (via svcbPortFor, the same source the SVCB
// row's `port=` SvcParam uses, so the TLSA owner name and the
// advertised port agree). Plaintext `http` endpoints are skipped —
// there is no TLS to bind. When the collected port set is empty (no
// endpoints, or all plaintext) the 443 fallback fires so a ServerCert
// always gets a cert-binding record.
//
// Ports are sorted numerically ascending. Deterministic order is
// load-bearing twice: the TL canonical-bytes invariant
// (ComputeRequiredDNSRecords feeds the V2 leaf hash) and the V1
// revoke map's injectivity (v1event keys the DNSRecordsToRemove map on
// Name, so distinct `_<port>._tcp.` names must stay distinct — which
// requires ports be deduped). The sort is numeric, not lexical: port
// 443 sorts before 1024 even though "_1024" < "_443" as strings.
//
// Required=false: TLSA is only meaningful when the operator's zone is
// DNSSEC-signed, which is a runtime property the domain layer cannot
// know. The verify layer enforces a stricter rule at query time: when
// a TLSA response IS DNSSEC-validated, its value MUST match the
// expected fingerprint (otherwise an attacker rewrote the record in
// a signed zone — the worst failure mode). That post-verify check
// lives alongside the verifier (lifecycle.go), not in the record set.
//
// `3 0 1 <hex>` = DANE-EE + full-certificate + SHA-256 (RFC 6698).
// Selector 0 (full cert), not 1 (SPKI): the hex is
// ServerCert.Fingerprint, which is SHA-256 over the full DER cert (see
// internal/crypto/x509.go CertificateFingerprint), so selector 0 is
// what actually matches those bytes. Selector 0 ties the binding to
// full-cert reissuance — the TLSA value changes on every cert rotation
// even when the key is unchanged. Surviving rotation (RFC 7671 §5.1's
// 3 1 1 SPKI-hash preference) would need a dedicated SPKI-hash helper,
// not CertificateFingerprint.
func TLSARecord(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	if reg.ServerCert == nil {
		return nil
	}

	ports := tlsPorts(reg.Endpoints)

	records := make([]domain.ExpectedDNSRecord, 0, len(ports))
	for _, port := range ports {
		records = append(records, domain.ExpectedDNSRecord{
			Name:     fmt.Sprintf("_%d._tcp.%s", port, reg.FQDN()),
			Type:     domain.DNSRecordTLSA,
			Value:    fmt.Sprintf("3 0 1 %s", reg.ServerCert.Fingerprint),
			Purpose:  domain.PurposeCertificateBinding,
			Required: false,
			TTL:      3600,
		})
	}
	return records
}

// tlsPorts returns the distinct TLS endpoint ports, sorted numerically
// ascending. Plaintext `http` endpoints are skipped. An empty result
// (no endpoints, or all plaintext) falls back to {443} so the cert
// binding always has a home.
func tlsPorts(endpoints []domain.AgentEndpoint) []int {
	seen := make(map[int]struct{}, len(endpoints))
	for _, ep := range endpoints {
		if isPlaintextHTTP(ep.AgentURL) {
			continue
		}
		seen[svcbPortFor(ep.AgentURL)] = struct{}{}
	}
	if len(seen) == 0 {
		return []int{443}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// isPlaintextHTTP reports whether agentURL uses the plaintext `http`
// scheme (no TLS to bind). Any other scheme — including a malformed or
// schemeless URL — is treated as TLS, matching svcbPortFor's
// default-to-443 posture: a TLSA record for an endpoint we can't fully
// parse is harmless (Required=false), but skipping one would silently
// drop a cert binding.
func isPlaintextHTTP(agentURL string) bool {
	if agentURL == "" {
		return false
	}
	u, err := url.Parse(agentURL)
	if err != nil {
		return false
	}
	return u.Scheme == schemeHTTP
}
