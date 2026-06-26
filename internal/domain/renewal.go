package domain

import (
	"fmt"
	"time"
)

const renewalExpiryDuration = 7 * 24 * time.Hour // 7 days.

// RenewalValidation tracks the ACME challenge state for a renewal.
//
// OrderRef and Challenges mirror the registration aggregate's
// CertOrder: CSR renewals carry the provider order created by
// `ServerCertificateIssuer.CreateOrder`; BYOC renewals carry
// self-issued challenges (OrderRef empty) because domain control must
// still be proven before the operator's certificate goes live.
type RenewalValidation struct {
	OrderRef   string           `json:"orderRef,omitempty"`
	Challenges []Challenge      `json:"challenges,omitempty"`
	Status     ValidationStatus `json:"status"`
	CreatedAt  time.Time        `json:"createdAt"`
	ExpiresAt  time.Time        `json:"expiresAt"`
	UpdatedAt  time.Time        `json:"updatedAt"`
}

// ChallengeOfType returns the first challenge of the given type.
func (v RenewalValidation) ChallengeOfType(t ChallengeType) (Challenge, bool) {
	for _, c := range v.Challenges {
		if c.Type == t {
			return c, true
		}
	}
	return Challenge{}, false
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
// only validates domain control via the order's challenges then flips
// the registration's ServerCert to the new leaf.
//
// The order is self-issued (see NewSelfIssuedOrder) — no certificate
// provider participates in a BYOC renewal. The renewal's validation
// window is the shorter of the standard renewal expiry and the
// order's own expiry.
func NewBYOCRenewal(
	agentID string,
	registrationID int64,
	byocCertPEM string,
	byocChainPEM string,
	order CertificateOrder,
	now time.Time,
) *ServerCertificateRenewal {
	return &ServerCertificateRenewal{
		AgentID:        agentID,
		RegistrationID: registrationID,
		RenewalType:    RenewalTypeBYOC,
		ByocCertPEM:    byocCertPEM,
		ByocChainPEM:   byocChainPEM,
		CreatedAt:      now,
		Validation:     newRenewalValidation(order, now),
	}
}

// NewCSRRenewal creates a new server-CSR renewal. The CSR is
// expected to already be persisted in `agent_csrs` with
// status=PENDING — this struct only references it by ID.
// Matches the reference's `AgentServerCertificateRenewal` with
// `renewalType = SERVER_CSR`.
//
// The order comes from the configured `ServerCertificateIssuer` port
// (`CreateOrder`), so the challenges relayed to the operator are the
// provider's own — for an ACME provider that means the provider's
// token + key authorization, not RA-invented values.
func NewCSRRenewal(
	agentID string,
	registrationID int64,
	csrID string,
	order CertificateOrder,
	now time.Time,
) *ServerCertificateRenewal {
	return &ServerCertificateRenewal{
		AgentID:        agentID,
		RegistrationID: registrationID,
		RenewalType:    RenewalTypeCSR,
		ServerCsrID:    csrID,
		CreatedAt:      now,
		Validation:     newRenewalValidation(order, now),
	}
}

// newRenewalValidation builds the embedded validation block from an
// order. The validation window is clamped to the order's expiry when
// the provider's order ends before the standard renewal window —
// relaying a challenge the provider will no longer accept would send
// the operator on a dead-end errand.
func newRenewalValidation(order CertificateOrder, now time.Time) RenewalValidation {
	expires := now.Add(renewalExpiryDuration)
	if !order.ExpiresAt.IsZero() && order.ExpiresAt.Before(expires) {
		expires = order.ExpiresAt
	}
	return RenewalValidation{
		OrderRef:   order.OrderRef,
		Challenges: order.Challenges,
		Status:     ValidationPending,
		CreatedAt:  now,
		ExpiresAt:  expires,
		UpdatedAt:  now,
	}
}

// IsExpired returns true if the validation has expired.
func (r *ServerCertificateRenewal) IsExpired(now time.Time) bool {
	return r.Validation.IsExpiredWithoutVerification(now)
}

// IsCompleted reports whether the renewal reached its terminal
// completed/failed state — i.e. CompletedAt is set (MarkCompleted or
// MarkFailed). It is NOT true merely because validation was verified:
// a CSR renewal whose order is still ISSUING is VERIFIED but not yet
// completed, and the operator must re-POST verify-acme to finish it.
func (r *ServerCertificateRenewal) IsCompleted() bool {
	return !r.CompletedAt.IsZero()
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
