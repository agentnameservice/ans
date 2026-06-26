// Package cert provides certificate-handling adapter implementations:
// the self-signed identity CA and the BYOC server-certificate validator.
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
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// SelfCA implements port.IdentityCertificateAuthority with an in-process
// ECDSA P-256 root CA. The root key and certificate are persisted under
// <dataDir> on first run and reused on subsequent runs.
type SelfCA struct {
	dataDir     string
	org         string
	validity    time.Duration
	identityTTL time.Duration
	mu          sync.RWMutex
	rootCert    *x509.Certificate
	rootKey     crypto.Signer
	revoked     map[string]struct{} // serial numbers (hex) of revoked certs
}

// SelfCAOption configures the CA at construction time.
type SelfCAOption func(*SelfCA)

// WithIdentityTTL sets the validity period of issued identity certificates.
// Default is 90 days.
func WithIdentityTTL(d time.Duration) SelfCAOption {
	return func(c *SelfCA) { c.identityTTL = d }
}

// NewSelfCA opens (or creates) a self-signed CA in the given directory.
// The root certificate has the organization name set to org and a validity
// of validityDays days.
func NewSelfCA(dataDir, org string, validityDays int, opts ...SelfCAOption) (*SelfCA, error) {
	if validityDays <= 0 {
		return nil, errors.New("cert: validity-days must be positive")
	}
	c := &SelfCA{
		dataDir:     dataDir,
		org:         org,
		validity:    time.Duration(validityDays) * 24 * time.Hour,
		identityTTL: 90 * 24 * time.Hour,
		revoked:     make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cert: create dir: %w", err)
	}
	if err := c.loadOrCreateRoot(); err != nil {
		return nil, err
	}
	return c, nil
}

// IssueIdentityCertificate signs the given CSR. The resulting certificate
// has the provided ANS name as a URI SAN and is valid for identityTTL.
func (c *SelfCA) IssueIdentityCertificate(
	ctx context.Context,
	csrPEM string,
	ansName string,
) (*port.IssuedCert, error) {
	csr, err := anscrypto.ValidateIdentityCSR(csrPEM, ansName)
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
	uri, err := url.Parse(ansName)
	if err != nil {
		return nil, fmt.Errorf("cert: parse ansName as URI: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-time.Minute), // small clock-skew tolerance
		NotAfter:              now.Add(c.identityTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{uri},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("cert: create certificate: %w", err)
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

// RevokeCertificate marks a certificate as revoked by serial.
// Idempotent per the port contract. The in-process CRL is not
// published; revocations are tracked in memory (and authoritatively
// through transparency-log events) — production deployments that need
// CRL/OCSP distribution swap in a cloud private-CA adapter at this
// port.
func (c *SelfCA) RevokeCertificate(
	ctx context.Context,
	req port.RevokeCertificateRequest,
) error {
	if req.SerialNumber == "" {
		return errors.New("cert: revoke: serial number is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[req.SerialNumber] = struct{}{}
	return nil
}

// GetCACertificate returns the root certificate PEM.
func (c *SelfCA) GetCACertificate(ctx context.Context) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootCert.Raw})
	return string(pemBytes), nil
}

// IsRevoked reports whether the given serial has been revoked in-process.
func (c *SelfCA) IsRevoked(serialHex string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.revoked[serialHex]
	return ok
}

// loadOrCreateRoot reads the existing root keypair if present, otherwise
// generates a new root certificate.
func (c *SelfCA) loadOrCreateRoot() error {
	keyPath := filepath.Join(c.dataDir, "root.key")
	certPath := filepath.Join(c.dataDir, "root.crt")

	if _, err := os.Stat(keyPath); err == nil {
		return c.loadRoot(keyPath, certPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cert: stat root: %w", err)
	}
	return c.createRoot(keyPath, certPath)
}

func (c *SelfCA) loadRoot(keyPath, certPath string) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cert: read root key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != pemTypePrivateKey {
		return errors.New("cert: root key is not a PKCS#8 PRIVATE KEY PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cert: parse root key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("cert: root key is not a signer")
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("cert: read root cert: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("cert: root cert is not a CERTIFICATE PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cert: parse root cert: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootKey = signer
	c.rootCert = cert
	return nil
}

func (c *SelfCA) createRoot(keyPath, certPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("cert: generate root key: %w", err)
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
			CommonName:   c.org + " Identity CA",
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
		return fmt.Errorf("cert: create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("cert: parse created root: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("cert: marshal root key: %w", err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: privDER}), 0o600); err != nil {
		return fmt.Errorf("cert: write root key: %w", err)
	}
	// 0o644 (world-readable) is intentional: the root cert is a
	// public artifact (verifiers fetch it to validate issued certs).
	// Private key path above is 0o600.
	if err := os.WriteFile(certPath, //nolint:gosec // G306: public cert, world-readable is by design
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("cert: write root cert: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootKey = priv
	c.rootCert = rootCert
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
