package domain

import "time"

// EventType classifies a domain event.
type EventType string

const (
	EventAgentRegistered EventType = "AGENT_REGISTERED"
	EventAgentActivated  EventType = "AGENT_ACTIVATED"
	EventAgentDeprecated EventType = "AGENT_DEPRECATED"
	EventAgentRevoked    EventType = "AGENT_REVOKED"
	EventAgentRenewed    EventType = "AGENT_RENEWED"
	EventCertRequested   EventType = "CERT_REQUESTED"
	EventCertIssued      EventType = "CERT_ISSUED"
	EventCertRevoked     EventType = "CERT_REVOKED"
)

// Event is the interface all domain events implement.
type Event interface {
	// Type returns the event type identifier.
	Type() EventType
	// OccurredAt returns when the event occurred.
	OccurredAt() time.Time
	// AgentID returns the agent this event relates to.
	AgentID() string
}

// AgentRegisteredEvent is published when a new agent registration is received.
type AgentRegisteredEvent struct {
	agentID   string
	ansName   AnsName
	ownerID   string
	timestamp time.Time
}

// NewAgentRegisteredEvent creates a new registration event.
func NewAgentRegisteredEvent(agentID string, ansName AnsName, ownerID string, at time.Time) AgentRegisteredEvent {
	return AgentRegisteredEvent{agentID: agentID, ansName: ansName, ownerID: ownerID, timestamp: at}
}

func (e AgentRegisteredEvent) Type() EventType       { return EventAgentRegistered }
func (e AgentRegisteredEvent) OccurredAt() time.Time { return e.timestamp }
func (e AgentRegisteredEvent) AgentID() string       { return e.agentID }

// AnsName returns the ANS name from the event.
func (e AgentRegisteredEvent) AnsName() AnsName { return e.ansName }

// OwnerID returns the owner identifier.
func (e AgentRegisteredEvent) OwnerID() string { return e.ownerID }

// AgentActivatedEvent is published when an agent transitions to ACTIVE.
type AgentActivatedEvent struct {
	agentID   string
	ansName   AnsName
	timestamp time.Time
}

// NewAgentActivatedEvent creates a new activation event.
func NewAgentActivatedEvent(agentID string, ansName AnsName, at time.Time) AgentActivatedEvent {
	return AgentActivatedEvent{agentID: agentID, ansName: ansName, timestamp: at}
}

func (e AgentActivatedEvent) Type() EventType       { return EventAgentActivated }
func (e AgentActivatedEvent) OccurredAt() time.Time { return e.timestamp }
func (e AgentActivatedEvent) AgentID() string       { return e.agentID }

// AnsName returns the ANS name from the event.
func (e AgentActivatedEvent) AnsName() AnsName { return e.ansName }

// AgentDeprecatedEvent is published when an agent is deprecated (superseded by new version).
type AgentDeprecatedEvent struct {
	agentID        string
	ansName        AnsName
	supersededByID string
	timestamp      time.Time
}

// NewAgentDeprecatedEvent creates a new deprecation event.
func NewAgentDeprecatedEvent(agentID string, ansName AnsName, supersededByID string, at time.Time) AgentDeprecatedEvent {
	return AgentDeprecatedEvent{agentID: agentID, ansName: ansName, supersededByID: supersededByID, timestamp: at}
}

func (e AgentDeprecatedEvent) Type() EventType       { return EventAgentDeprecated }
func (e AgentDeprecatedEvent) OccurredAt() time.Time { return e.timestamp }
func (e AgentDeprecatedEvent) AgentID() string       { return e.agentID }

// SupersededByID returns the ID of the agent that supersedes this one.
func (e AgentDeprecatedEvent) SupersededByID() string { return e.supersededByID }

// AgentRevokedEvent is published when an agent is revoked.
type AgentRevokedEvent struct {
	agentID   string
	ansName   AnsName
	reason    RevocationReason
	timestamp time.Time
}

// NewAgentRevokedEvent creates a new revocation event.
func NewAgentRevokedEvent(agentID string, ansName AnsName, reason RevocationReason, at time.Time) AgentRevokedEvent {
	return AgentRevokedEvent{agentID: agentID, ansName: ansName, reason: reason, timestamp: at}
}

func (e AgentRevokedEvent) Type() EventType       { return EventAgentRevoked }
func (e AgentRevokedEvent) OccurredAt() time.Time { return e.timestamp }
func (e AgentRevokedEvent) AgentID() string       { return e.agentID }

// Reason returns the revocation reason.
func (e AgentRevokedEvent) Reason() RevocationReason { return e.reason }

// CertRequestedEvent is published when a certificate signing request is submitted.
type CertRequestedEvent struct {
	agentID   string
	csrID     string
	certType  CertificateType
	timestamp time.Time
}

// NewCertRequestedEvent creates a new CSR event.
func NewCertRequestedEvent(agentID, csrID string, certType CertificateType, at time.Time) CertRequestedEvent {
	return CertRequestedEvent{agentID: agentID, csrID: csrID, certType: certType, timestamp: at}
}

func (e CertRequestedEvent) Type() EventType       { return EventCertRequested }
func (e CertRequestedEvent) OccurredAt() time.Time { return e.timestamp }
func (e CertRequestedEvent) AgentID() string       { return e.agentID }

// CSRID returns the CSR identifier.
func (e CertRequestedEvent) CSRID() string { return e.csrID }

// CertType returns the certificate type.
func (e CertRequestedEvent) CertType() CertificateType { return e.certType }
