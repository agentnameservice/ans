package domain

import (
	"fmt"
	"time"
)

const (
	maxDisplayNameLength = 64
	maxDescriptionLength = 150
)

// RegistrationDetails holds metadata about an agent registration.
type RegistrationDetails struct {
	RegistrationTimestamp time.Time `json:"registrationTimestamp"`
	LastRenewalTimestamp  time.Time `json:"lastRenewalTimestamp,omitzero"`
	DisplayName           string    `json:"agentDisplayName,omitempty"`
	Description           string    `json:"agentDescription,omitempty"`
}

// EffectiveTimestamp returns the last renewal timestamp if set, otherwise the registration timestamp.
func (d RegistrationDetails) EffectiveTimestamp() time.Time {
	if !d.LastRenewalTimestamp.IsZero() {
		return d.LastRenewalTimestamp
	}
	return d.RegistrationTimestamp
}

// WithRenewal returns a copy with the renewal timestamp updated.
func (d RegistrationDetails) WithRenewal(at time.Time) RegistrationDetails {
	d.LastRenewalTimestamp = at
	return d
}

// AgentRegistration is the aggregate root for agent registrations.
// It manages the lifecycle of an agent from registration through activation,
// deprecation, and revocation.
type AgentRegistration struct {
	// ID is the database primary key (zero for unsaved registrations).
	ID int64 `json:"id,omitempty"`

	// AgentID is the immutable UUID that persists across versions.
	AgentID string `json:"agentId"`

	// OwnerID identifies the authenticated user who owns this registration.
	OwnerID string `json:"ownerId"`

	// AnsName is the versioned agent name (ans://v1.0.0.agent.example.com).
	AnsName AnsName `json:"ansName"`

	// Status is the current lifecycle state.
	Status RegistrationStatus `json:"status"`

	// Details holds display name, description, and timestamps.
	Details RegistrationDetails `json:"details"`

	// Endpoints are the agent's protocol endpoints.
	Endpoints []AgentEndpoint `json:"endpoints"`

	// ServerCert is the BYOC server certificate (if submitted).
	ServerCert *ByocServerCertificate `json:"serverCert,omitempty"`

	// IdentityCSR is the most recent identity CSR on this
	// registration: PENDING between registration and verify-acme
	// (which signs it once domain control is proven), and SIGNED
	// thereafter. A rotation via POST /certificates/identity is signed
	// at submission and replaces this slot with the new SIGNED CSR.
	// Historical CSRs persist in the csrs table — the one embedded
	// here is a "fast path" cache for the status handler.
	IdentityCSR *AgentCSR `json:"identityCsr,omitempty"`

	// ServerCSR is the most recent pending server CSR on this
	// registration, if any. Only set when the operator uses the
	// CA-signed server-cert path (POST /certificates/server). BYOC
	// registrations leave this nil.
	ServerCSR *AgentCSR `json:"serverCsr,omitempty"`

	// SupersedesRegistrationID is the ID of the previous version (for supersession).
	SupersedesRegistrationID int64 `json:"supersedesRegistrationId,omitempty"`

	// CertOrder tracks the certificate order and its domain-control
	// challenges for this registration. CSR-path registrations carry
	// the provider order returned by `ServerCertificateIssuer.
	// CreateOrder`; BYOC registrations carry a self-issued validation
	// order (OrderRef empty) because domain control must be proven
	// even when no certificate is being issued. Zero-value for
	// registrations predating order persistence.
	CertOrder CertificateOrder `json:"certOrder,omitzero"`

	// PendingEvents holds domain events raised during this aggregate operation.
	// They are cleared after being published.
	PendingEvents []Event `json:"-"`
}

// NewRegistration creates a new agent registration in PENDING_VALIDATION state.
func NewRegistration(
	agentID string,
	ownerID string,
	ansName AnsName,
	displayName string,
	description string,
	endpoints []AgentEndpoint,
	serverCert *ByocServerCertificate,
	identityCSR *AgentCSR,
	now time.Time,
) (*AgentRegistration, error) {
	if agentID == "" {
		return nil, NewValidationError("MISSING_AGENT_ID", "agentId is required")
	}
	if ownerID == "" {
		return nil, NewValidationError("MISSING_OWNER_ID", "ownerId is required")
	}
	if ansName.IsZero() {
		return nil, NewValidationError("MISSING_ANS_NAME", "ansName is required")
	}
	if len(displayName) > maxDisplayNameLength {
		return nil, NewValidationError(
			"DISPLAY_NAME_TOO_LONG",
			fmt.Sprintf("displayName exceeds %d characters", maxDisplayNameLength),
		)
	}
	if len(description) > maxDescriptionLength {
		return nil, NewValidationError(
			"DESCRIPTION_TOO_LONG",
			fmt.Sprintf("description exceeds %d characters", maxDescriptionLength),
		)
	}
	if len(endpoints) == 0 {
		return nil, NewValidationError("MISSING_ENDPOINTS", "at least one endpoint is required")
	}

	// Validate endpoints against the agent host.
	eps := AgentEndpoints{AgentID: agentID, Endpoints: endpoints}
	if err := eps.Validate(ansName.FQDN()); err != nil {
		return nil, err
	}

	// Validate server cert matches FQDN if provided.
	if serverCert != nil && !serverCert.MatchesFQDN(ansName.FQDN()) {
		return nil, NewCertificateError(
			"SERVER_CERT_FQDN_MISMATCH",
			fmt.Sprintf("server certificate does not match agent FQDN %q", ansName.FQDN()),
		)
	}

	reg := &AgentRegistration{
		AgentID: agentID,
		OwnerID: ownerID,
		AnsName: ansName,
		Status:  StatusPendingValidation,
		Details: RegistrationDetails{
			RegistrationTimestamp: now,
			DisplayName:           displayName,
			Description:           description,
		},
		Endpoints:   endpoints,
		ServerCert:  serverCert,
		IdentityCSR: identityCSR,
	}

	reg.addEvent(NewAgentRegisteredEvent(agentID, ansName, ownerID, now))
	return reg, nil
}

// SubmitIdentityCSR replaces the registration's pending identity CSR
// with a new one. Requires status == ACTIVE — per the reference RA's
// `CertificateOperationsHandler.submitAgentIdentityCsr`:
// "Agent must be ACTIVE to submit identity CSR". The caller is
// expected to have validated the CSR PEM before calling this.
//
// Returns the new CSR so the caller can persist it both on the
// aggregate (via Save) and in the csrs table (for historical lookup).
func (r *AgentRegistration) SubmitIdentityCSR(csrID, csrPEM string, now time.Time) (*AgentCSR, error) {
	if r.Status != StatusActive {
		return nil, NewInvalidStateError(
			"AGENT_NOT_ACTIVE",
			fmt.Sprintf("Agent must be ACTIVE to submit identity CSR. Current status: %s", r.Status),
		)
	}
	csr := NewIdentityCSR(csrID, csrPEM, now)
	r.IdentityCSR = &csr
	return &csr, nil
}

// SubmitServerCSR replaces the registration's pending server CSR
// with a new one. The reference RA's equivalent is in
// `CertificateOperationsHandler.submitAgentServerCsr` and it does NOT
// gate on status — server CSRs can be submitted at any state since
// operators may want the RA-signed path before the agent is live. The
// caller is expected to have validated the CSR PEM.
func (r *AgentRegistration) SubmitServerCSR(csrID, csrPEM string, now time.Time) (*AgentCSR, error) {
	csr := NewServerCSR(csrID, csrPEM, now)
	r.ServerCSR = &csr
	return &csr, nil
}

// Activate transitions the registration from a pending state to ACTIVE.
func (r *AgentRegistration) Activate(now time.Time) error {
	// Allow activation from PENDING_DNS (normal flow) or any pending state (fast-track).
	if !r.Status.IsPending() {
		return NewInvalidStateError(
			"CANNOT_ACTIVATE",
			fmt.Sprintf("cannot activate agent in status %s", r.Status),
		)
	}
	r.Status = StatusActive
	r.addEvent(NewAgentActivatedEvent(r.AgentID, r.AnsName, now))
	return nil
}

// AdvanceToPendingDNS transitions from PENDING_VALIDATION to PENDING_DNS,
// which is the state the registration enters once domain-control
// validation (ACME) succeeds AND the certificate order completed —
// the DNS records the operator must configure (notably TLSA) can only
// be computed once the server certificate exists.
//
// The agent lifecycle enum stays exactly as the V2 spec's
// `AgentLifecycleStatus` defines it. Certificate issuance in flight is
// NOT a lifecycle state: it is tracked on `CertOrder.State`
// (PENDING → ISSUING → COMPLETED) and surfaced as derived views —
// `RegistrationPending.status = PENDING_CERTS` and `AgentStatus.phase
// = CERTIFICATE_ISSUANCE` — while the lifecycle status remains
// PENDING_VALIDATION. Synchronous issuers (the self-signed CA) pass
// through the ISSUING window in-process; asynchronous issuers (ACME
// providers) park the agent there until a re-driven verify-acme
// finalizes the order.
func (r *AgentRegistration) AdvanceToPendingDNS() error {
	return r.transitionTo(StatusPendingDNS)
}

// Deprecate transitions an ACTIVE registration to DEPRECATED.
func (r *AgentRegistration) Deprecate(supersededByID string, now time.Time) error {
	if err := r.transitionTo(StatusDeprecated); err != nil {
		return err
	}
	r.addEvent(NewAgentDeprecatedEvent(r.AgentID, r.AnsName, supersededByID, now))
	return nil
}

// Revoke transitions the registration to REVOKED. Only ACTIVE or DEPRECATED
// registrations may be revoked via this method; use Cancel() to revoke a
// pending registration. This keeps the two semantically distinct user
// actions on separate methods.
//
// The two rejection paths are reported with distinct error codes:
//   - CANNOT_REVOKE_PENDING: caller is holding a pending registration and
//     should be using Cancel() instead (different event metadata).
//   - INVALID_STATUS_TRANSITION: caller is holding a terminal-state
//     registration (already REVOKED / FAILED / EXPIRED) — nothing to do.
//
// Splitting them lets API consumers give actionable feedback rather than
// lumping "wrong state" into a single code.
func (r *AgentRegistration) Revoke(reason RevocationReason, now time.Time) error {
	if !reason.IsValid() {
		return NewValidationError("INVALID_REVOCATION_REASON", fmt.Sprintf("invalid reason: %q", reason))
	}
	if r.Status.IsPending() {
		return NewInvalidStateError(
			"CANNOT_REVOKE_PENDING",
			fmt.Sprintf("use Cancel() to terminate a pending registration (current status: %s)", r.Status),
		)
	}
	if err := r.transitionTo(StatusRevoked); err != nil {
		return err
	}
	r.addEvent(NewAgentRevokedEvent(r.AgentID, r.AnsName, reason, now))
	return nil
}

// Cancel transitions a PENDING registration to REVOKED.
//
// Eligibility follows the spec's revoke-route contract: the
// PENDING_CERTS phase (order ISSUING or terminally FAILED) and
// PENDING_DNS are cancellable; a registration still awaiting its
// domain-control challenge (PENDING_VALIDATION with the order
// PENDING) is not — it auto-expires when the challenge window
// lapses. Legacy registrations without a persisted order are
// cancellable: they have no challenge window to expire on, so cancel
// is their only exit.
func (r *AgentRegistration) Cancel(now time.Time) error {
	// Validation-class (422), not invalid-state (409): Cancel is
	// reached only through the revoke route, whose canonical spec
	// documents 422 for an unprocessable request and carries no 409.
	if !r.Status.IsPending() {
		return NewValidationError(
			"CANNOT_CANCEL",
			fmt.Sprintf("can only cancel pending registrations, current status: %s", r.Status),
		)
	}
	if r.Status == StatusPendingValidation && r.CertOrder.State == OrderStatePending {
		return NewValidationError(
			"CANNOT_CANCEL",
			"registration is awaiting domain validation and will auto-expire when the challenge window lapses",
		)
	}
	r.Status = StatusRevoked
	r.addEvent(NewAgentRevokedEvent(r.AgentID, r.AnsName, RevocationCessationOfOperation, now))
	return nil
}

// Fail transitions a PENDING registration to FAILED.
func (r *AgentRegistration) Fail() error {
	if !r.Status.IsPending() {
		return NewInvalidStateError(
			"CANNOT_FAIL",
			fmt.Sprintf("can only fail pending registrations, current status: %s", r.Status),
		)
	}
	r.Status = StatusFailed
	return nil
}

// Expire transitions a PENDING registration to EXPIRED.
func (r *AgentRegistration) Expire() error {
	if !r.Status.IsPending() {
		return NewInvalidStateError(
			"CANNOT_EXPIRE",
			fmt.Sprintf("can only expire pending registrations, current status: %s", r.Status),
		)
	}
	r.Status = StatusExpired
	return nil
}

// AllowsSupersede returns true if this registration can be superseded by a new version.
func (r *AgentRegistration) AllowsSupersede(newVersion SimplifiedSemVer) bool {
	if r.Status != StatusActive {
		return false
	}
	return newVersion.GreaterThan(r.AnsName.Version())
}

// FQDN returns the lowercase FQDN from the ANS name.
func (r *AgentRegistration) FQDN() string {
	return r.AnsName.FQDN()
}

// ClearEvents returns and clears the pending domain events.
func (r *AgentRegistration) ClearEvents() []Event {
	events := r.PendingEvents
	r.PendingEvents = nil
	return events
}

func (r *AgentRegistration) transitionTo(target RegistrationStatus) error {
	if err := r.Status.ValidateTransition(target); err != nil {
		return err
	}
	r.Status = target
	return nil
}

func (r *AgentRegistration) addEvent(event Event) {
	r.PendingEvents = append(r.PendingEvents, event)
}
