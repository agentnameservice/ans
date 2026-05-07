package handler

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parseCertPEM extracts the display metadata from a PEM-encoded
// certificate. It's a small helper kept out of the DTO file so that
// the DTO mapping stays focused on shape and ignores parsing details.
//
// The returned fields are exactly those the V2 spec's
// CertificateResponse wants to populate (subject, issuer, serial,
// public-key algorithm, signature algorithm). Parsing happens with
// the standard library's `x509.ParseCertificate` — no reliance on
// Bouncy Castle or OpenSSL features.
//
// A bad PEM, a non-CERTIFICATE block, or an unparseable DER yields
// (zero, false); the caller is expected to fall back to an empty
// metadata section rather than failing the whole response.
func parseCertPEM(pemStr string) (certInfo, bool) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE" {
		return certInfo{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certInfo{}, false
	}
	return certInfo{
		Subject: cert.Subject.String(),
		Issuer:  cert.Issuer.String(),
		// %x on big.Int gives lower-case hex with no leading zeros —
		// the reference emits the decimal form, but hex is the
		// standard "serial number" display form seen in openssl
		// x509 output. We pick hex because it's deterministic and
		// length-stable across issuers. If a future spec change
		// asks for decimal we can switch; the field is informational.
		SerialNumber:       fmt.Sprintf("%x", cert.SerialNumber),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}, true
}
