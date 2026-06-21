package domain

import (
	"fmt"
	"net/url"
)

// DNSRecordType represents a DNS record type.
type DNSRecordType string

const (
	DNSRecordTXT   DNSRecordType = "TXT"
	DNSRecordTLSA  DNSRecordType = "TLSA"
	DNSRecordHTTPS DNSRecordType = "HTTPS"
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
// tlPublicBaseURL is the externally-reachable Transparency Log URL used in
// the _ans-badge record (e.g. "https://tl.example.org"). When non-empty the
// badge url= field points to the TL badge endpoint for this agent; when
// empty it falls back to the agent's own endpoint URL.
func ComputeRequiredDNSRecords(reg *AgentRegistration, tlPublicBaseURL string) []ExpectedDNSRecord {
	fqdn := reg.FQDN()
	// Version is emitted as a bare semver string ("1.2.0"). The
	// `v`-prefixed form only appears inside the ANS name's hostname
	// label — TXT record payloads carry the machine-readable semver
	// directly, matching the shape a client would parse with any
	// semver library.
	version := reg.AnsName.Version().String()
	var records []ExpectedDNSRecord

	// _ans TXT record for each protocol endpoint — agent discovery.
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

	// _ans-badge TXT record — trust badge. Required alongside _ans:
	// resolvers and badge-verifying clients expect to find both, and
	// publishing _ans without _ans-badge would advertise an agent
	// that fails the public discovery handshake.
	if len(reg.Endpoints) > 0 {
		badgeURL := reg.Endpoints[0].AgentURL
		if tlPublicBaseURL != "" && reg.AgentID != "" {
			// tlPublicBaseURL is validated at config load (https, no
			// query/fragment/userinfo), so JoinPath cannot fail here.
			badgeURL, _ = url.JoinPath(tlPublicBaseURL, "v1", "agents", reg.AgentID)
		}
		badgeValue := fmt.Sprintf("v=ans-badge1; version=%s; url=%s",
			version, badgeURL)
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
	// (issued via the configured `ServerCertificateIssuer`). Both
	// paths land through the same ByocServerCertificate struct, so
	// `reg.ServerCert` is set for any registration that's reached
	// verify-dns.
	if reg.ServerCert == nil {
		return records
	}
	records = append(records, TLSARecordForCert(fqdn, reg.ServerCert.Fingerprint))

	return records
}

// TLSARecordForCert builds the DANE-EE TLSA record binding a server
// certificate fingerprint to the FQDN. Shared between the
// registration record set and the renewal status responses (the
// operator updates this record after every renewal — it fingerprints
// the new leaf).
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
func TLSARecordForCert(fqdn, fingerprint string) ExpectedDNSRecord {
	return ExpectedDNSRecord{
		Name:     fmt.Sprintf("_443._tcp.%s", fqdn),
		Type:     DNSRecordTLSA,
		Value:    fmt.Sprintf("3 1 1 %s", fingerprint),
		Purpose:  PurposeCertificateBinding,
		Required: false,
		TTL:      3600,
	}
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
