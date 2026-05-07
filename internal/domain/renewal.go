package domain

import (
	"fmt"
	"time"
)

const renewalExpiryDuration = 7 * 24 * time.Hour // 7 days.

// RenewalValidation tracks the ACME challenge state for a renewal.
type RenewalValidation struct {
	DNS01ChallengeToken  string           `json:"dns01ChallengeToken"`
	HTTP01ChallengeToken string           `json:"http01ChallengeToken"`
	Status               ValidationStatus `json:"status"`
	CreatedAt            time.Time        `json:"createdAt"`
	ExpiresAt            time.Time        `json:"expiresAt"`
	UpdatedAt            time.Time        `json:"updatedAt"`
}

// IsExpiredWithoutVerification returns true if the validation expired before being verified.
func (v RenewalValidation) IsExpiredWithoutVerification(now time.Time) bool {
	return now.After(v.ExpiresAt) && v.Status != ValidationVerified
}

// MarkVerified transitions the validation to VERIFIED.
func (v RenewalValidation) MarkVerified(now time.Time) (RenewalValidation, error) {
	if v.Status != ValidationPending {
		return v, NewInvalidStateError(
			"VALIDATION_NOT_PENDING",
			fmt.Sprintf("cannot verify validation in status %s", v.Status),
		)
	}
	v.Status = ValidationVerified
	v.UpdatedAt = now
	return v, nil
}

// MarkFailed transitions the validation to FAILED.
func (v RenewalValidation) MarkFailed(now time.Time) (RenewalValidation, error) {
	if v.Status != ValidationPending {
		return v, NewInvalidStateError(
			"VALIDATION_NOT_PENDING",
			fmt.Sprintf("cannot fail validation in status %s", v.Status),
		)
	}
	v.Status = ValidationFailed
	v.UpdatedAt = now
	return v, nil
}

// ServerCertificateRenewal is the aggregate root for server certificate renewals.
type ServerCertificateRenewal struct {
	ID             int64       `json:"id,omitempty"`
	AgentID        string      `json:"agentId"`
	RegistrationID int64       `json:"registrationId"`
	RenewalType    RenewalType `json:"renewalType"`
	// ServerCsrID is set when RenewalType == SERVER_CSR. Points at
	// the CSR row in `agent_csrs` that this renewal was initiated
	// with. Empty for BYOC renewals.
	ServerCsrID   string            `json:"serverCsrId,omitempty"`
	ByocCertPEM   string            `json:"byocCertPem,omitempty"`
	ByocChainPEM  string            `json:"byocChainPem,omitempty"`
	FailureReason string            `json:"failureReason,omitempty"`
	CompletedAt   time.Time         `json:"completedAt,omitzero"`
	CreatedAt     time.Time         `json:"createdAt"`
	Validation    RenewalValidation `json:"validation"`
}

// NewBYOCRenewal creates a new BYOC server certificate renewal.
// The operator supplies the already-issued certificate; the renewal
// only validates domain control via ACME then flips the registration's
// ServerCert to the new leaf.
func NewBYOCRenewal(
	agentID string,
	registrationID int64,
	byocCertPEM string,
	byocChainPEM string,
	dns01Token string,
	http01Token string,
	now time.Time,
) *ServerCertificateRenewal {
	return &ServerCertificateRenewal{
		AgentID:        agentID,
		RegistrationID: registrationID,
		RenewalType:    RenewalTypeBYOC,
		ByocCertPEM:    byocCertPEM,
		ByocChainPEM:   byocChainPEM,
		CreatedAt:      now,
		Validation: RenewalValidation{
			DNS01ChallengeToken:  dns01Token,
			HTTP01ChallengeToken: http01Token,
			Status:               ValidationPending,
			CreatedAt:            now,
			ExpiresAt:            now.Add(renewalExpiryDuration),
			UpdatedAt:            now,
		},
	}
}

// NewCSRRenewal creates a new server-CSR renewal. The CSR is
// expected to already be persisted in `agent_csrs` with
// status=PENDING — this struct only references it by ID.
// Matches the reference's `AgentServerCertificateRenewal` with
// `renewalType = SERVER_CSR`.
func NewCSRRenewal(
	agentID string,
	registrationID int64,
	csrID string,
	dns01Token string,
	http01Token string,
	now time.Time,
) *ServerCertificateRenewal {
	return &ServerCertificateRenewal{
		AgentID:        agentID,
		RegistrationID: registrationID,
		RenewalType:    RenewalTypeCSR,
		ServerCsrID:    csrID,
		CreatedAt:      now,
		Validation: RenewalValidation{
			DNS01ChallengeToken:  dns01Token,
			HTTP01ChallengeToken: http01Token,
			Status:               ValidationPending,
			CreatedAt:            now,
			ExpiresAt:            now.Add(renewalExpiryDuration),
			UpdatedAt:            now,
		},
	}
}

// IsExpired returns true if the validation has expired.
func (r *ServerCertificateRenewal) IsExpired(now time.Time) bool {
	return r.Validation.IsExpiredWithoutVerification(now)
}

// IsCompleted returns true if the renewal reached a terminal state.
func (r *ServerCertificateRenewal) IsCompleted() bool {
	return !r.CompletedAt.IsZero() || r.Validation.Status == ValidationVerified
}

// MarkCompleted marks the renewal as successfully completed.
func (r *ServerCertificateRenewal) MarkCompleted(now time.Time) error {
	if !r.CompletedAt.IsZero() {
		return NewInvalidStateError("ALREADY_COMPLETED", "renewal is already completed")
	}
	r.CompletedAt = now
	return nil
}

// MarkFailed marks the renewal as failed with a reason.
func (r *ServerCertificateRenewal) MarkFailed(reason string, now time.Time) error {
	if !r.CompletedAt.IsZero() {
		return NewInvalidStateError("ALREADY_COMPLETED", "cannot fail a completed renewal")
	}
	r.FailureReason = reason
	r.CompletedAt = now
	return nil
}

// UpdateValidationStatus updates the embedded validation.
func (r *ServerCertificateRenewal) UpdateValidationStatus(v RenewalValidation) {
	r.Validation = v
}
