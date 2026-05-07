// Package crypto provides shared cryptographic operations used by the
// RA and TL: X.509 parsing, CSR validation, JWS signing/verification,
// JSON Canonicalization (RFC 8785), and COSE_Sign1 receipt encoding.
//
// Every function validates its inputs and returns typed errors. Nothing
// in this package panics on malformed input.
package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Minimum key strengths enforced on submitted CSRs and certificates.
// These match current NIST recommendations and CA/Browser Forum
// Baseline Requirements for publicly trusted certificates.
const (
	MinRSAKeyBits = 2048
)

// AllowedSignatureAlgorithms is the allowlist of signature algorithms
// we accept on CSRs and certificates. Weaker algorithms (MD5, SHA-1)
// are rejected even if technically parseable.
//
//nolint:gochecknoglobals // crypto-policy allowlist; treated as immutable
var AllowedSignatureAlgorithms = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA,
	x509.SHA384WithRSA,
	x509.SHA512WithRSA,
	x509.SHA256WithRSAPSS,
	x509.SHA384WithRSAPSS,
	x509.SHA512WithRSAPSS,
	x509.ECDSAWithSHA256,
	x509.ECDSAWithSHA384,
	x509.ECDSAWithSHA512,
}

// Sentinel errors for inspection.
var (
	ErrPEMParse         = errors.New("crypto: could not parse PEM")
	ErrCertParse        = errors.New("crypto: could not parse certificate")
	ErrCSRParse         = errors.New("crypto: could not parse CSR")
	ErrWeakAlgorithm    = errors.New("crypto: signature algorithm not allowed")
	ErrWeakKey          = errors.New("crypto: key does not meet minimum strength")
	ErrInvalidSignature = errors.New("crypto: invalid signature on CSR or certificate")
	ErrFQDNMismatch     = errors.New("crypto: certificate CN/SAN does not match expected FQDN")
	ErrCertNotYetValid  = errors.New("crypto: certificate is not yet valid")
	ErrCertExpired      = errors.New("crypto: certificate is expired")
	ErrChainInvalid     = errors.New("crypto: certificate chain is invalid")
)

// ParseCertificatePEM parses a single PEM-encoded X.509 certificate.
func ParseCertificatePEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE block", ErrPEMParse)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertParse, err)
	}
	return cert, nil
}

// ParseCertificateChainPEM parses a PEM bundle that may contain multiple
// certificates. Returns the certificates in document order.
func ParseCertificateChainPEM(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCertParse, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ParseCSRPEM parses a PEM-encoded certificate signing request and
// verifies its self-signature.
func ParseCSRPEM(pemData string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE REQUEST block", ErrPEMParse)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCSRParse, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return csr, nil
}

// CheckSignatureAlgorithm returns nil if the given algorithm is on the
// allowlist of accepted algorithms, or ErrWeakAlgorithm otherwise.
func CheckSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	if slices.Contains(AllowedSignatureAlgorithms, alg) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrWeakAlgorithm, alg)
}

// CheckKeyStrength verifies that the public key in the given certificate
// or CSR meets the minimum strength requirements.
func CheckKeyStrength(pub any) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < MinRSAKeyBits {
			return fmt.Errorf("%w: RSA key is %d bits, minimum %d", ErrWeakKey, key.N.BitLen(), MinRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		// Only accept P-256 and P-384.
		bits := key.Curve.Params().BitSize
		if bits != 256 && bits != 384 {
			return fmt.Errorf("%w: ECDSA curve %s not allowed", ErrWeakKey, key.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrWeakKey, pub)
	}
	return nil
}

// CertificateFingerprint returns the lowercase hex SHA-256 fingerprint
// of the certificate's DER encoding.
func CertificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// VerifyChain verifies leaf against the given intermediates with an
// optional custom root pool. Pass nil for roots to use the system roots.
// In local-dev, a nil roots pool plus a self-signed leaf will fail —
// callers should use SkipVerifyChain in that case.
func VerifyChain(leaf *x509.Certificate, chain []*x509.Certificate, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, c := range chain {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Use current time; caller can wrap in their own clock if needed.
		CurrentTime: time.Now(),
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("%w: %w", ErrChainInvalid, err)
	}
	return nil
}

// MatchCertificateToFQDN returns nil if the certificate's CN or one of
// its DNS SANs exactly matches (case-insensitive) the expected FQDN.
func MatchCertificateToFQDN(cert *x509.Certificate, expectedFQDN string) error {
	expected := strings.ToLower(strings.TrimSpace(expectedFQDN))
	if expected == "" {
		return fmt.Errorf("%w: expected FQDN is empty", ErrFQDNMismatch)
	}

	if strings.EqualFold(cert.Subject.CommonName, expected) {
		return nil
	}
	for _, san := range cert.DNSNames {
		if strings.EqualFold(san, expected) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q not in CN or SANs", ErrFQDNMismatch, expected)
}

// CheckCertificateValidity returns nil if the certificate is currently
// within its validity period.
func CheckCertificateValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: NotBefore=%s", ErrCertNotYetValid, cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: NotAfter=%s", ErrCertExpired, cert.NotAfter)
	}
	return nil
}
