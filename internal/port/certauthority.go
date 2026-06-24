package port

import (
	"context"
	"errors"
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

// IssuedCert is returned by a certificate issuer after signing a CSR.
type IssuedCert struct {
	CertPEM      string
	ChainPEM     string
	SerialNumber string
	// CertificateRef is the issuer's opaque handle for the issued
	// certificate — an ACME certificate URL, a cloud CA resource name
	// (GCP CAS) or ARN (AWS PCA), empty for the in-process self-signed
	// CAs. Persisted alongside the certificate because some providers
	// revoke by handle rather than by serial.
	CertificateRef string
	ExpiresAt      time.Time
	IssuedAt       time.Time
}

// RevokeCertificateRequest identifies a certificate to revoke at its
// issuer. SerialNumber (lowercase hex) is always populated;
// CertificateRef carries the provider handle captured at issuance
// when one exists. Implementations use whichever their API keys on —
// serial for the self-signed CA, AWS PCA, and Vault; resource name
// for GCP CAS.
//
// Revocation MUST be idempotent: revoking an already-revoked
// certificate returns nil. The caller performs CA revocation before
// committing its own transaction, so a crash between the two is
// healed by a retried call.
type RevokeCertificateRequest struct {
	SerialNumber   string
	CertificateRef string
	Reason         domain.RevocationReason
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

// IdentityCertificateAuthority issues identity certificates from a
// PRIVATE trust root — identity certs are never publicly issued. The
// CA binds the versioned ANS name as a URI SAN, creating the
// verifiable link between an agent and its declared version.
//
// Because the trust root is private, no domain-control challenge
// lifecycle exists on this port: domain ownership is proven by the
// server-certificate flow (the verify-acme gate, plus the public
// provider's own validation on the ACME path) BEFORE the RA asks this
// port to sign anything. Issuance is therefore a plain CSR-in /
// cert-out call.
//
// The in-process default is the file-backed SelfCA. Cloud private CAs
// (AWS Private CA, GCP Private CA Service, Vault PKI) slot in at this
// boundary; adapter notes for them:
//
//   - All three accept CSRs. AWS PCA issues asynchronously — the
//     adapter does a short bounded poll (IssueCertificate →
//     GetCertificate), the same in-call pattern the ACME server
//     issuer uses. No pending/order state is needed: no third party
//     or operator action intervenes, so a retryable error suffices
//     and the caller's idempotent re-entry re-drives.
//   - The URI SAN is the load-bearing field. The ansName parameter is
//     passed alongside the CSR so adapters can either verify the
//     CSR's URI SAN (the SelfCA approach) or stamp it API-side. The
//     provider must be configured to permit URI SANs and a
//     ClientAuth EKU (PCA: a CSR/API-passthrough template; CAS: pool
//     issuance policy; Vault: role allowed_uri_sans).
//   - Issuance should be idempotent under retry: derive the
//     provider's idempotency token (PCA IdempotencyToken, CAS
//     request_id) from a hash of the CSR PEM, which is stable per
//     CSR row.
type IdentityCertificateAuthority interface {
	// IssueIdentityCertificate signs the given identity CSR and returns
	// the resulting certificate plus chain.
	IssueIdentityCertificate(
		ctx context.Context,
		csrPEM string,
		ansName string,
	) (*IssuedCert, error)

	// RevokeCertificate revokes a previously issued certificate at the
	// CA, so private CRL/OCSP distribution reflects the revocation —
	// the RA's own database flip and transparency-log emit are the
	// caller's responsibility. Must be idempotent (see
	// RevokeCertificateRequest).
	RevokeCertificate(
		ctx context.Context,
		req RevokeCertificateRequest,
	) error

	// GetCACertificate returns the CA's root certificate PEM.
	// Clients use this to build trust chains.
	GetCACertificate(ctx context.Context) (string, error)
}

// ErrOrderPending is returned by ServerCertificateIssuer.FinalizeOrder
// when the provider accepted the finalize request but has not produced
// a certificate yet (e.g. an ACME order sitting in `processing`). The
// caller persists the order as ISSUING and re-drives the finalize on a
// subsequent verify-acme call. Wrap with %w so errors.Is matches.
var ErrOrderPending = errors.New("certificate order pending")

// ErrOrderFailed is returned by ServerCertificateIssuer.FinalizeOrder
// when the provider reported a terminal order failure (e.g. an ACME
// order moved to `invalid`). The order cannot be retried; the operator
// must submit a new registration or renewal. Wrap with %w so errors.Is
// matches.
var ErrOrderFailed = errors.New("certificate order failed")

// FinalizeOrderRequest carries everything an issuer needs to complete
// a previously created order.
type FinalizeOrderRequest struct {
	// OrderRef is the provider-opaque handle returned by CreateOrder
	// (an ACME order URL, an internal id, …).
	OrderRef string
	// CSRPEM is the operator-submitted server CSR. Per RFC 8555 the
	// CSR is presented at finalize time, not at order creation.
	CSRPEM string
	// FQDN is the agent host the certificate must cover.
	FQDN string
	// Verified lists the challenge types whose artifacts the RA's own
	// pre-flight check found published. ACME implementations MUST only
	// answer a verified challenge: telling the provider to validate an
	// unsatisfied challenge invalidates the authorization — and with it
	// the whole order. Self-signed implementations may ignore it (the
	// RA's gate is authoritative there).
	Verified []domain.ChallengeType
}

// ServerCertificateIssuer issues server-auth TLS certificates through
// a certificate-order lifecycle:
//
//  1. CreateOrder — called at registration / renewal-submission time.
//     The returned domain-control challenges are relayed verbatim to
//     the domain owner in the pending response. ANS never publishes
//     challenge artifacts on the owner's behalf.
//  2. FinalizeOrder — called from verify-acme after the RA confirmed
//     at least one challenge artifact is published. Synchronous
//     issuers return the certificate immediately; asynchronous ones
//     return ErrOrderPending and the order is re-driven on the next
//     verify-acme call.
//
// The local implementation is the file-backed self-signed CA under
// `internal/adapter/cert`, which self-issues its challenge tokens and
// finalizes in-process. External providers slot in at this boundary
// without touching the service layer — e.g. an ACME adapter (Let's
// Encrypt) maps CreateOrder to new-order (relaying the provider's
// token + key authorization and the computed DNS digest), and
// FinalizeOrder to challenge-answer → poll → finalize → download.
// Proprietary CAs (managed-CA APIs, AWS Private CA, GCP CAS) map the
// same way, returning no challenges from CreateOrder when they perform
// no domain validation of their own.
//
// The server-cert trust root is distinct from the identity CA so the
// two can be rotated and key-managed independently.
type ServerCertificateIssuer interface {
	// CreateOrder opens an issuance order for the agent's FQDN and
	// returns the provider's domain-control challenges. The CSR is NOT
	// required yet (matching ACME, where the CSR is presented at
	// finalize). The returned order is persisted on the registration
	// or renewal aggregate.
	CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error)

	// FinalizeOrder completes the order: the issuer validates domain
	// control by its own rules (or trusts the RA's gate, for the
	// self-signed CA), signs the CSR, and returns the leaf + chain.
	// Returns ErrOrderPending while an asynchronous provider is still
	// processing, and ErrOrderFailed when the order is terminally
	// dead.
	FinalizeOrder(ctx context.Context, req FinalizeOrderRequest) (*IssuedCert, error)

	// GetCACertificate returns the server CA's root certificate PEM.
	// Distinct from the identity CA's root — operators publish this
	// separately so relying parties building TLS trust stores can
	// trust it without trusting the identity CA. Publicly trusted
	// providers (ACME) return their chain root; it is informational
	// there since relying parties already hold it in system stores.
	GetCACertificate(ctx context.Context) (string, error)
}
