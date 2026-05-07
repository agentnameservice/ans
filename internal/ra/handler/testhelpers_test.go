package handler_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// newTestCSR builds a valid PEM-encoded ECDSA P-256 identity CSR
// whose URI SAN is `ansName`. The RA's X509Validator requires the
// URI SAN to match the ANS name it's validating against, so tests
// constructing registrations MUST use a CSR whose URI SAN equals the
// ANS name.
func newTestCSR(t *testing.T, ansName string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ansName)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: ansName},
		URIs:               []*url.URL{u},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// selfSignedLeafAndChain returns a PEM-encoded self-signed server
// cert (leaf) + its own single-cert chain for BYOC-path tests. The
// demo validator runs with WithSkipChainVerify, so a self-signed
// cert is accepted. The returned chain is the same cert repeated to
// satisfy the "chainPEM present when leaf is present" rule some
// downstream code enforces.
func selfSignedLeafAndChain(t *testing.T, fqdn string) (leafPEM, chainPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fqdn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{fqdn},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	chainPEM = leafPEM
	return leafPEM, chainPEM
}

// newTestServerCSR builds a server CSR with the given FQDN as a
// DNS SAN — the shape the RA's ValidateServerCSR expects. Distinct
// from newTestCSR which builds identity CSRs with URI SAN.
func newTestServerCSR(t *testing.T, fqdn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: fqdn},
		DNSNames:           []string{fqdn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
