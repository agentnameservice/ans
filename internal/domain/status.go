package domain

import (
	"fmt"
	"slices"
)

// RegistrationStatus represents the lifecycle state of an agent registration.
type RegistrationStatus string

const (
	StatusPendingValidation RegistrationStatus = "PENDING_VALIDATION"
	StatusPendingDNS        RegistrationStatus = "PENDING_DNS"
	StatusActive            RegistrationStatus = "ACTIVE"
	StatusDeprecated        RegistrationStatus = "DEPRECATED"
	StatusRevoked           RegistrationStatus = "REVOKED"
	StatusFailed            RegistrationStatus = "FAILED"
	StatusExpired           RegistrationStatus = "EXPIRED"
)

// IsValid returns true if the status is a recognized value.
func (s RegistrationStatus) IsValid() bool {
	switch s {
	case StatusPendingValidation, StatusPendingDNS,
		StatusActive, StatusDeprecated, StatusRevoked, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

// IsPending returns true if the status is any pending state.
// The V2 lifecycle has exactly two pending states: PENDING_VALIDATION
// (registration created, awaiting ACME domain-control challenge) and
// PENDING_DNS (challenge passed, awaiting operator DNS publication).
func (s RegistrationStatus) IsPending() bool {
	switch s {
	case StatusPendingValidation, StatusPendingDNS:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the status is a terminal state (no further transitions).
func (s RegistrationStatus) IsTerminal() bool {
	switch s {
	case StatusRevoked, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

// String returns the status as a string.
func (s RegistrationStatus) String() string { return string(s) }

// ValidTransitions defines the allowed state transitions.
// Key is the current state; value is the set of valid target states.
//
//nolint:gochecknoglobals // domain-level state-machine table; immutable
var ValidTransitions = map[RegistrationStatus][]RegistrationStatus{
	StatusPendingValidation: {StatusPendingDNS, StatusFailed, StatusRevoked, StatusExpired},
	StatusPendingDNS:        {StatusActive, StatusFailed, StatusRevoked, StatusExpired},
	StatusActive:            {StatusDeprecated, StatusRevoked},
	StatusDeprecated:        {StatusRevoked},
	// Terminal states: no outgoing transitions.
	StatusRevoked: {},
	StatusFailed:  {},
	StatusExpired: {},
}

// CanTransitionTo returns true if moving from the current status to the target is valid.
func (s RegistrationStatus) CanTransitionTo(target RegistrationStatus) bool {
	allowed, ok := ValidTransitions[s]
	if !ok {
		return false
	}
	return slices.Contains(allowed, target)
}

// ValidateTransition returns nil if the transition is valid, or an error otherwise.
func (s RegistrationStatus) ValidateTransition(target RegistrationStatus) error {
	if !s.CanTransitionTo(target) {
		return NewInvalidStateError(
			"INVALID_STATUS_TRANSITION",
			fmt.Sprintf("cannot transition from %s to %s", s, target),
		)
	}
	return nil
}

// CertificateStatus represents the status of a stored certificate.
type CertificateStatus string

const (
	CertStatusPending CertificateStatus = "PENDING"
	CertStatusValid   CertificateStatus = "VALID"
	CertStatusRevoked CertificateStatus = "REVOKED"
)

// CertificateType classifies a certificate as server or identity.
type CertificateType string

const (
	CertTypeServer   CertificateType = "SERVER"
	CertTypeIdentity CertificateType = "IDENTITY"
)

// CSRStatus represents the processing status of a certificate signing request.
type CSRStatus string

const (
	CSRStatusPending  CSRStatus = "PENDING"
	CSRStatusSigned   CSRStatus = "SIGNED"
	CSRStatusRejected CSRStatus = "REJECTED"
)

// ValidationStatus represents the status of an ACME validation.
type ValidationStatus string

const (
	ValidationPending  ValidationStatus = "PENDING"
	ValidationVerified ValidationStatus = "VERIFIED"
	ValidationFailed   ValidationStatus = "FAILED"
)

// RenewalType classifies a server certificate renewal. Matches the
// V2 `ServerCertificateRenewalRequest.renewalType` enum (§1422) and
// the reference RA's `RenewalType` enum byte-for-byte.
type RenewalType string

const (
	RenewalTypeBYOC RenewalType = "SERVER_BYOC"
	RenewalTypeCSR  RenewalType = "SERVER_CSR"
)

// RevocationReason represents why an agent was revoked.
type RevocationReason string

const (
	RevocationKeyCompromise        RevocationReason = "KEY_COMPROMISE"
	RevocationCessationOfOperation RevocationReason = "CESSATION_OF_OPERATION"
	RevocationAffiliationChanged   RevocationReason = "AFFILIATION_CHANGED"
	RevocationSuperseded           RevocationReason = "SUPERSEDED"
	RevocationCertificateHold      RevocationReason = "CERTIFICATE_HOLD"
	RevocationPrivilegeWithdrawn   RevocationReason = "PRIVILEGE_WITHDRAWN"
	RevocationAACompromise         RevocationReason = "AA_COMPROMISE"
)

// IsValid returns true if the revocation reason is a recognized value.
func (r RevocationReason) IsValid() bool {
	switch r {
	case RevocationKeyCompromise, RevocationCessationOfOperation,
		RevocationAffiliationChanged, RevocationSuperseded,
		RevocationCertificateHold, RevocationPrivilegeWithdrawn,
		RevocationAACompromise:
		return true
	default:
		return false
	}
}

// String returns the reason as a string.
func (r RevocationReason) String() string { return string(r) }
