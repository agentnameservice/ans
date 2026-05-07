package port

import (
	"context"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ValidatedCert is the result of successfully parsing and validating
// a BYOC server certificate. It carries all the fields the domain needs
// without exposing x509 internals.
type ValidatedCert struct {
	LeafPEM      string
	ChainPEM     string
	CN           string
	SANs         []string
	IssuerDN     string
	ValidFrom    time.Time
	ValidTo      time.Time
	Fingerprint  string // SHA-256, lowercase hex
	SerialNumber string
}

// IssuedCert is returned by the identity CA after signing a CSR.
type IssuedCert struct {
	CertPEM      string
	ChainPEM     string
	SerialNumber string
	ExpiresAt    time.Time
	IssuedAt     time.Time
}

// CertificateValidator validates operator-provided server certificates
// and identity CSRs without issuing anything. It is used at the edges
// of the system (registration, renewal) to prevent malformed or
// mismatched certificates from entering the domain model.
type CertificateValidator interface {
	// ValidateServerCertificate verifies a BYOC server certificate against
	// the expected FQDN. It checks PEM parsing, chain validity, CN/SAN
	// matching, validity period, signature algorithm, and key strength.
	ValidateServerCertificate(
		ctx context.Context,
		leafPEM, chainPEM, expectedFQDN string,
	) (*ValidatedCert, error)

	// ValidateIdentityCSR verifies an identity CSR before it is signed.
	// It checks PEM parsing, signature, key strength, and that the URI SAN
	// matches the expected ANS name.
	ValidateIdentityCSR(
		ctx context.Context,
		csrPEM string,
		expectedAnsName string,
	) error

	// ValidateServerCSR verifies a server CSR before issuance. Server
	// CSRs must carry the agent's FQDN as a DNS SAN (TLS server-auth
	// convention). Falls back to matching against the CSR subject CN
	// for SDK-compat when no SAN is present.
	ValidateServerCSR(
		ctx context.Context,
		csrPEM string,
		expectedFQDN string,
	) error
}

// IdentityCertificateAuthority issues identity certificates from the
// system's private CA. The CA binds the versioned ANS name as a URI SAN,
// creating the verifiable link between an agent and its declared version.
type IdentityCertificateAuthority interface {
	// IssueIdentityCertificate signs the given identity CSR and returns
	// the resulting certificate plus chain.
	IssueIdentityCertificate(
		ctx context.Context,
		csrPEM string,
		ansName string,
	) (*IssuedCert, error)

	// RevokeCertificate marks a previously issued certificate as revoked.
	// Implementations should track revocations so issued certs can be
	// cross-referenced.
	RevokeCertificate(
		ctx context.Context,
		serialNumber string,
		reason domain.RevocationReason,
	) error

	// GetCACertificate returns the CA's root certificate PEM.
	// Clients use this to build trust chains.
	GetCACertificate(ctx context.Context) (string, error)
}

// ServerCertificateAuthority issues server-auth TLS certificates from
// a private CA that is distinct from the identity CA (so the two can
// be rotated and key-managed independently).
//
// The reference RA delegates to an internal ACME-style cert service;
// local and LF-submittable deployments ship a file-backed self-signed
// CA under `internal/adapter/cert`. The port is stable so cloud-adapter
// contributions (AWS Private CA, GCP CAS, a hosted ACME CA, etc.) can
// replace the implementation without touching the service layer.
type ServerCertificateAuthority interface {
	// IssueServerCertificate signs the given server CSR for the
	// agent's FQDN. The CSR must carry the FQDN as a DNS SAN (the
	// standard TLS server-auth shape); implementations call
	// CertificateValidator.ValidateServerCSR before touching the
	// signing key. Returns the leaf certificate + chain PEM + validity
	// metadata.
	IssueServerCertificate(
		ctx context.Context,
		csrPEM string,
		fqdn string,
	) (*IssuedCert, error)

	// GetCACertificate returns the server CA's root certificate PEM.
	// Distinct from the identity CA's root — operators publish this
	// separately so relying parties building TLS trust stores can
	// trust it without trusting the identity CA.
	GetCACertificate(ctx context.Context) (string, error)
}
