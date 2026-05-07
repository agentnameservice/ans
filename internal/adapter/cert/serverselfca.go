package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// ServerSelfCA implements port.ServerCertificateAuthority with an
// in-process ECDSA P-256 root CA that signs TLS server-auth
// certificates.
//
// This is the local / LF-submittable implementation. The reference
// RA delegates to an internal ACME-style cert service, and any cloud
// adapter (AWS Private CA, GCP CAS, hosted ACME CA) can replace
// ServerSelfCA without touching the service layer — the port
// (ServerCertificateAuthority) is the stable contract.
//
// Kept distinct from SelfCA (the identity CA) so operators can
// rotate the two roots independently and publish the server-CA
// trust anchor separately from the identity-CA trust anchor.
// Operators that want to consolidate the two can wire the same
// SelfCA instance behind both ports; there's no functional
// difference at the x509 layer, only a key-management convention.
type ServerSelfCA struct {
	dataDir   string
	org       string
	validity  time.Duration
	serverTTL time.Duration
	mu        sync.RWMutex
	rootCert  *x509.Certificate
	rootKey   crypto.Signer
}

// ServerSelfCAOption configures the server CA at construction time.
type ServerSelfCAOption func(*ServerSelfCA)

// WithServerCertTTL sets the validity period of issued server certs.
// Default is 90 days — matches the reference RA's ACME-style rolling
// validity.
func WithServerCertTTL(d time.Duration) ServerSelfCAOption {
	return func(c *ServerSelfCA) { c.serverTTL = d }
}

// NewServerSelfCA opens (or creates) a self-signed server CA in the
// given directory. The root certificate has the organization name
// set to org and a validity of validityDays days.
//
// The CA key and certificate are persisted under <dataDir> as
// `server-root.key` / `server-root.crt` (note the `server-` prefix
// so they coexist with the identity CA's `root.key` / `root.crt`).
func NewServerSelfCA(dataDir, org string, validityDays int, opts ...ServerSelfCAOption) (*ServerSelfCA, error) {
	if validityDays <= 0 {
		return nil, errors.New("cert: server CA validity-days must be positive")
	}
	c := &ServerSelfCA{
		dataDir:   dataDir,
		org:       org,
		validity:  time.Duration(validityDays) * 24 * time.Hour,
		serverTTL: 90 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cert: create server-ca dir: %w", err)
	}
	if err := c.loadOrCreateRoot(); err != nil {
		return nil, err
	}
	return c, nil
}

// IssueServerCertificate signs the given server CSR. The resulting
// certificate has the provided FQDN as a DNS SAN and the standard
// TLS server-auth EKU, and is valid for serverTTL.
func (c *ServerSelfCA) IssueServerCertificate(
	ctx context.Context,
	csrPEM string,
	fqdn string,
) (*port.IssuedCert, error) {
	csr, err := anscrypto.ValidateServerCSR(csrPEM, fqdn)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	rootCert, rootKey := c.rootCert, c.rootKey
	c.mu.RUnlock()

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("cert: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(c.serverTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Server-auth EKU — this is the shape mainstream TLS clients
		// (browsers, curl) demand before trusting a cert for HTTPS.
		// Differs from the identity CA's ClientAuth EKU.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{fqdn},
		// Subject is lifted from the CSR; some SDK-generated CSRs set
		// CN to a placeholder rather than the FQDN. We keep CN for
		// back-compat but the DNS SAN is the authoritative binding.
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("cert: create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})

	return &port.IssuedCert{
		CertPEM:      string(certPEM),
		ChainPEM:     string(chainPEM),
		SerialNumber: fmt.Sprintf("%x", serial),
		ExpiresAt:    template.NotAfter,
		IssuedAt:     template.NotBefore,
	}, nil
}

// GetCACertificate returns the server-CA root certificate PEM.
// Operators publish this separately from the identity-CA root so
// relying parties can trust server certs without also trusting
// identity certs (or vice versa).
func (c *ServerSelfCA) GetCACertificate(ctx context.Context) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootCert.Raw})
	return string(pemBytes), nil
}

// loadOrCreateRoot reads the existing root keypair if present,
// otherwise generates one.
func (c *ServerSelfCA) loadOrCreateRoot() error {
	keyPath := filepath.Join(c.dataDir, "server-root.key")
	certPath := filepath.Join(c.dataDir, "server-root.crt")

	if _, err := os.Stat(keyPath); err == nil {
		return c.loadRoot(keyPath, certPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cert: stat server-root: %w", err)
	}
	return c.createRoot(keyPath, certPath)
}

func (c *ServerSelfCA) loadRoot(keyPath, certPath string) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cert: read server-root key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("cert: server-root key is not a PKCS#8 PRIVATE KEY PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cert: parse server-root key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("cert: server-root key is not a signer")
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("cert: read server-root cert: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("cert: server-root cert is not a CERTIFICATE PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cert: parse server-root cert: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootKey = signer
	c.rootCert = cert
	return nil
}

func (c *ServerSelfCA) createRoot(keyPath, certPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("cert: generate server-root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{c.org},
			CommonName:   c.org + " Server CA",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(c.validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return fmt.Errorf("cert: create server-root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("cert: parse server-root: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("cert: marshal server-root key: %w", err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return fmt.Errorf("cert: write server-root key: %w", err)
	}
	// 0o644 (world-readable) is intentional: the server-root cert
	// is a public artifact. Key path above is 0o600.
	if err := os.WriteFile(certPath, //nolint:gosec // G306: public cert, world-readable is by design
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("cert: write server-root cert: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootKey = priv
	c.rootCert = rootCert
	return nil
}
