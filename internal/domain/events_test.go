package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAgentRegisteredEvent(t *testing.T) {
	name, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	now := time.Now()
	e := NewAgentRegisteredEvent("agent-1", name, "owner-1", now)

	assert.Equal(t, EventAgentRegistered, e.Type())
	assert.Equal(t, now, e.OccurredAt())
	assert.Equal(t, "agent-1", e.AgentID())
	assert.Equal(t, name, e.AnsName())
	assert.Equal(t, "owner-1", e.OwnerID())
}

func TestAgentActivatedEvent(t *testing.T) {
	name, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	now := time.Now()
	e := NewAgentActivatedEvent("agent-1", name, now)

	assert.Equal(t, EventAgentActivated, e.Type())
	assert.Equal(t, now, e.OccurredAt())
	assert.Equal(t, "agent-1", e.AgentID())
	assert.Equal(t, name, e.AnsName())
}

func TestAgentDeprecatedEvent(t *testing.T) {
	name, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	now := time.Now()
	e := NewAgentDeprecatedEvent("agent-1", name, "new-id", now)

	assert.Equal(t, EventAgentDeprecated, e.Type())
	assert.Equal(t, now, e.OccurredAt())
	assert.Equal(t, "agent-1", e.AgentID())
	assert.Equal(t, "new-id", e.SupersededByID())
}

func TestAgentRevokedEvent(t *testing.T) {
	name, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	now := time.Now()
	e := NewAgentRevokedEvent("agent-1", name, RevocationKeyCompromise, now)

	assert.Equal(t, EventAgentRevoked, e.Type())
	assert.Equal(t, now, e.OccurredAt())
	assert.Equal(t, "agent-1", e.AgentID())
	assert.Equal(t, RevocationKeyCompromise, e.Reason())
}

func TestCertRequestedEvent(t *testing.T) {
	now := time.Now()
	e := NewCertRequestedEvent("agent-1", "csr-1", CertTypeIdentity, now)

	assert.Equal(t, EventCertRequested, e.Type())
	assert.Equal(t, now, e.OccurredAt())
	assert.Equal(t, "agent-1", e.AgentID())
	assert.Equal(t, "csr-1", e.CSRID())
	assert.Equal(t, CertTypeIdentity, e.CertType())
}
