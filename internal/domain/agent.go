package domain

import (
	"fmt"
	"time"
)

const (
	maxDisplayNameLength = 64
	maxDescriptionLength = 150
)

// ACMEChallenge captures the DNS-01 challenge token issued to an
// operator at registration time. Zero-value when no challenge is
// active (agent is past PENDING_DNS, or the registration predates
// challenge-persistence).
//
// ans emits DNS-01 only — the reference api-spec ChallengeInfo
// declares both DNS_01 and HTTP_01 options, but the ans deviation
// (documented in CLAUDE.md) skips HTTP_01. Future support can land
// by extending this struct with HTTP01Token + KeyAuthorization.
type ACMEChallenge struct {
	DNS01Token string    `json:"dns01Token,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt,omitzero"`
}

// IsZero reports whether the challenge is unset.
func (c ACMEChallenge) IsZero() bool {
	return c.DNS01Token == "" && c.ExpiresAt.IsZero()
}

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

	// IdentityCSR is the most recent pending identity CSR on this
	// registration. Initially populated at registration time; can be
	// replaced by a rotation via POST /certificates/identity (which
	// flips the previous one to SIGNED once the CA issues the new
	// cert). Historical CSRs persist in the csrs table — the one
	// embedded here is a "fast path" cache for the status handler.
	IdentityCSR *AgentCSR `json:"identityCsr,omitempty"`

	// ServerCSR is the most recent pending server CSR on this
	// registration, if any. Only set when the operator uses the
	// CA-signed server-cert path (POST /certificates/server). BYOC
	// registrations leave this nil.
	ServerCSR *AgentCSR `json:"serverCsr,omitempty"`

	// SupersedesRegistrationID is the ID of the previous version (for supersession).
	SupersedesRegistrationID int64 `json:"supersedesRegistrationId,omitempty"`

	// ACMEChallenge holds the DNS-01 challenge token issued at
	// registration time. Zero-value when the agent is past the
	// PENDING_DNS stage (or predates the challenge-persistence
	// migration). ans is DNS-01-only per the documented no-HTTP-01
	// deviation.
	ACMEChallenge ACMEChallenge `json:"acmeChallenge,omitzero"`

	// CapabilitiesHash is the SHA-256(JCS(agentCardContent)) digest
	// (hex-lowercase) the RA computed when the operator submitted
	// agentCardContent on the V2 registration request, per
	// ANS_SPEC.md §A.1. Empty when the operator did not submit
	// content. The activation flow seals this value into the
	// AGENT_REGISTERED event's attestations.metadataHashes under the
	// well-known key event.MetadataHashKeyCapabilitiesHash.
	//
	// Stored as a hex string rather than the raw 32-byte digest so
	// the storage column is human-readable and the wire format
	// matches the AIM's verification expectation directly.
	CapabilitiesHash string `json:"capabilitiesHash,omitempty"`

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
	if identityCSR == nil {
		return nil, NewValidationError("MISSING_IDENTITY_CSR", "identityCsrPEM is required")
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
// validation (ACME) succeeds and the DNS records the operator must
// configure have been computed.
//
// The V2 spec (spec/api-spec-v2.yaml) and the reference RA both use a
// three-state pending chain of PENDING_VALIDATION → PENDING_DNS →
// ACTIVE. There is no intermediate PENDING_CERTS state: certificate
// issuance is internal work that happens within either
// PENDING_VALIDATION or PENDING_DNS and does not need its own exposed
// lifecycle state.
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

// Cancel transitions a PENDING registration to REVOKED (idempotent cancel).
func (r *AgentRegistration) Cancel(now time.Time) error {
	if !r.Status.IsPending() {
		return NewInvalidStateError(
			"CANNOT_CANCEL",
			fmt.Sprintf("can only cancel pending registrations, current status: %s", r.Status),
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
