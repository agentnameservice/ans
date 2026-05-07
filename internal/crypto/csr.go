package crypto

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

// ValidateIdentityCSR verifies an identity CSR before it is signed.
// It checks: PEM parsing, self-signature, algorithm allowlist,
// key strength, and that a URI SAN matches the expected ANS name.
func ValidateIdentityCSR(csrPEM, expectedAnsName string) (*x509.CertificateRequest, error) {
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := CheckSignatureAlgorithm(csr.SignatureAlgorithm); err != nil {
		return nil, err
	}

	if err := CheckKeyStrength(csr.PublicKey); err != nil {
		return nil, err
	}

	// Identity CSRs must carry the versioned ANS name as a URI SAN.
	// CN matching is optional (PKI allows SAN-only), but the URI SAN
	// is the authoritative binding.
	if err := matchURISAN(csr.URIs, expectedAnsName); err != nil {
		return nil, err
	}

	return csr, nil
}

// ValidateServerCSR verifies a CSR intended for server-certificate
// issuance. Unlike the identity CSR (URI SAN = ANS name), server CSRs
// carry the agent's FQDN as a DNS SAN — the standard CA/Browser Forum
// shape for TLS server certs. Checks: PEM parsing, self-signature,
// algorithm allowlist, key strength, and that a DNS SAN (or CN as a
// fallback) matches the expected FQDN.
//
// Matches the reference RA's server-CSR validation path, which also
// requires the FQDN to appear as a DNS SAN because most public CAs
// have deprecated CN-only matching since CA/B Forum BR 2017.
func ValidateServerCSR(csrPEM, expectedFQDN string) (*x509.CertificateRequest, error) {
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := CheckSignatureAlgorithm(csr.SignatureAlgorithm); err != nil {
		return nil, err
	}

	if err := CheckKeyStrength(csr.PublicKey); err != nil {
		return nil, err
	}

	if err := matchDNSSAN(csr.DNSNames, csr.Subject.CommonName, expectedFQDN); err != nil {
		return nil, err
	}

	return csr, nil
}

// matchDNSSAN returns nil if the expected FQDN appears in the CSR's
// DNSNames list. Falls back to matching against the CSR subject CN
// as a compatibility path — some SDKs still set only CN and not a
// DNS SAN. If neither matches, returns ErrFQDNMismatch.
func matchDNSSAN(dnsNames []string, commonName, expectedFQDN string) error {
	expected := strings.TrimSpace(strings.ToLower(expectedFQDN))
	if expected == "" {
		return fmt.Errorf("%w: expected FQDN is empty", ErrFQDNMismatch)
	}
	for _, name := range dnsNames {
		if strings.EqualFold(strings.TrimSpace(name), expected) {
			return nil
		}
	}
	if strings.EqualFold(strings.TrimSpace(commonName), expected) {
		return nil
	}
	return fmt.Errorf("%w: no DNS SAN or CN matched %q (got SANs=%v, CN=%q)",
		ErrFQDNMismatch, expectedFQDN, dnsNames, commonName)
}

// matchURISAN returns nil if any URI in the given slice exactly matches
// the expected ANS name string (ans://vX.Y.Z.host).
//
// crypto/x509 guarantees parsed CSR `URIs` entries are non-nil — any
// malformed URI in the SAN extension would fail ParseCertificateRequest
// before we see it — so this loop does not need a nil guard.
func matchURISAN(uris []*url.URL, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return fmt.Errorf("%w: expected ANS name is empty", ErrFQDNMismatch)
	}
	for _, u := range uris {
		if u.String() == expected {
			return nil
		}
	}
	return fmt.Errorf("%w: no URI SAN matched %q", ErrFQDNMismatch, expected)
}
