package domain

import (
	"fmt"
	"slices"
	"time"
)

// AgentCSR represents a certificate signing request submitted by an
// agent — either an identity CSR (the initial and rotation path for
// the URI-SAN-bearing identity cert the RA's self-CA signs) or a
// server CSR (the server-certificate path used when the operator
// wants the RA to sign, as an alternative to BYOC).
//
// Mirrors the reference RA's `AgentCsr` type hierarchy, which splits
// into identity and server CSR variants. Go lacks a built-in
// discriminated-union type, so we discriminate on the `Type` field.
// Everything else matches byte-for-byte with the reference RA's
// `AgentCertificateSigningRequest` — same status transitions, same
// fields on the wire, same rejection-reason semantics.
type AgentCSR struct {
	CSRID               string    `json:"csrId"`
	Type                CSRType   `json:"type"`
	CSRContent          string    `json:"csrContent"`
	Status              CSRStatus `json:"status"`
	SubmissionTimestamp time.Time `json:"submissionTimestamp"`
	ProcessedTimestamp  time.Time `json:"processedTimestamp,omitzero"`
	RejectionReason     string    `json:"rejectionReason,omitempty"`
}

// CSRType distinguishes identity CSRs from server CSRs. Matches the
// V2 `CsrStatusResponse.type` enum (§1381) exactly.
type CSRType string

const (
	CSRTypeIdentity CSRType = "IDENTITY"
	CSRTypeServer   CSRType = "SERVER"
)

// NewIdentityCSR creates a new pending identity CSR.
func NewIdentityCSR(csrID, csrContent string, submittedAt time.Time) AgentCSR {
	return AgentCSR{
		CSRID:               csrID,
		Type:                CSRTypeIdentity,
		CSRContent:          csrContent,
		Status:              CSRStatusPending,
		SubmissionTimestamp: submittedAt,
	}
}

// NewServerCSR creates a new pending server CSR.
func NewServerCSR(csrID, csrContent string, submittedAt time.Time) AgentCSR {
	return AgentCSR{
		CSRID:               csrID,
		Type:                CSRTypeServer,
		CSRContent:          csrContent,
		Status:              CSRStatusPending,
		SubmissionTimestamp: submittedAt,
	}
}

// MarkSigned transitions the CSR to SIGNED status.
func (c AgentCSR) MarkSigned(processedAt time.Time) (AgentCSR, error) {
	if c.Status != CSRStatusPending {
		return c, NewInvalidStateError(
			"CSR_NOT_PENDING",
			fmt.Sprintf("cannot sign CSR in status %s", c.Status),
		)
	}
	c.Status = CSRStatusSigned
	c.ProcessedTimestamp = processedAt
	return c, nil
}

// MarkRejected transitions the CSR to REJECTED status with a reason.
func (c AgentCSR) MarkRejected(reason string, processedAt time.Time) (AgentCSR, error) {
	if c.Status != CSRStatusPending {
		return c, NewInvalidStateError(
			"CSR_NOT_PENDING",
			fmt.Sprintf("cannot reject CSR in status %s", c.Status),
		)
	}
	c.Status = CSRStatusRejected
	c.RejectionReason = reason
	c.ProcessedTimestamp = processedAt
	return c, nil
}

// StoredCertificate represents a certificate stored in the system.
type StoredCertificate struct {
	InternalID      int64           `json:"internalId"`
	CSRID           string          `json:"csrId"`
	CertificateType CertificateType `json:"certificateType"`
	CertificatePEM  string          `json:"certificatePem"`
	ChainPEM        string          `json:"chainPem,omitempty"`
	// SerialNumber is the issued certificate's serial (lowercase hex),
	// captured at issuance so CA-side revocation never re-parses the
	// PEM. Empty on rows persisted before serial tracking landed.
	SerialNumber string `json:"serialNumber,omitempty"`
	// CertificateRef is the issuing provider's opaque handle for this
	// certificate (cloud-CA resource name/ARN, ACME certificate URL).
	// Empty for the in-process self-signed CAs, which revoke by
	// serial alone.
	CertificateRef      string            `json:"certificateRef,omitempty"`
	Status              CertificateStatus `json:"status"`
	ExpirationTimestamp time.Time         `json:"expirationTimestamp"`
	IssueTimestamp      time.Time         `json:"issueTimestamp"`
}

// StoredCertificateFromByoc converts a BYOC server certificate into
// the StoredCertificate representation, matching the reference RA's
// `StoredCertificate.fromByoc` factory. Used by the cert-management
// service to present BYOC and CA-issued server certs through the same
// shape — the `GET /certificates/server` handler doesn't care which
// pathway produced the cert.
//
// csrId is empty for BYOC entries because the BYOC flow never
// involves a CSR on our side; the caller submitted a fully-formed
// cert. The DTO mapper in the handler layer tolerates the empty
// string (serializes as an omitted field).
func StoredCertificateFromByoc(byoc *ByocServerCertificate) *StoredCertificate {
	return &StoredCertificate{
		CSRID:               "",
		CertificateType:     CertTypeServer,
		CertificatePEM:      byoc.LeafCertificatePEM,
		ChainPEM:            byoc.ChainCertificatesPEM,
		Status:              CertStatusValid,
		IssueTimestamp:      byoc.ValidFromTimestamp,
		ExpirationTimestamp: byoc.ValidToTimestamp,
	}
}

// IsValid returns true if the certificate is valid (VALID status and not expired).
func (c StoredCertificate) IsValid(now time.Time) bool {
	return c.Status == CertStatusValid && now.Before(c.ExpirationTimestamp)
}

// Revoke returns a copy with REVOKED status.
func (c StoredCertificate) Revoke() StoredCertificate {
	c.Status = CertStatusRevoked
	return c
}

// ByocServerCertificate represents a Bring-Your-Own-Certificate server certificate.
type ByocServerCertificate struct {
	LeafCertificatePEM      string    `json:"leafCertificatePem"`
	ChainCertificatesPEM    string    `json:"chainCertificatesPem,omitempty"`
	SubjectCommonName       string    `json:"subjectCommonName"`
	SubjectAlternativeNames []string  `json:"subjectAlternativeNames"`
	IssuerDN                string    `json:"issuerDn"`
	ValidFromTimestamp      time.Time `json:"validFromTimestamp"`
	ValidToTimestamp        time.Time `json:"validToTimestamp"`
	Fingerprint             string    `json:"fingerprint"` // SHA-256
}

// IsValid returns true if the certificate is within its validity period.
func (c ByocServerCertificate) IsValid(now time.Time) bool {
	return !now.Before(c.ValidFromTimestamp) && now.Before(c.ValidToTimestamp)
}

// GetFullChain returns the leaf certificate concatenated with the chain.
func (c ByocServerCertificate) GetFullChain() string {
	if c.ChainCertificatesPEM == "" {
		return c.LeafCertificatePEM
	}
	return c.LeafCertificatePEM + "\n" + c.ChainCertificatesPEM
}

// MatchesFQDN returns true if the certificate CN or SANs include the expected FQDN.
func (c ByocServerCertificate) MatchesFQDN(fqdn string) bool {
	if c.SubjectCommonName == fqdn {
		return true
	}
	return slices.Contains(c.SubjectAlternativeNames, fqdn)
}
