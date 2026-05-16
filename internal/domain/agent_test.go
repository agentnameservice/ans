package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newValidRegistration builds a fully-validated AgentRegistration for tests.
func newValidRegistration(t *testing.T) *AgentRegistration {
	t.Helper()
	ansName, err := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	require.NoError(t, err)

	csr := NewIdentityCSR("csr-1", "-----BEGIN CSR-----", time.Now())

	endpoints := []AgentEndpoint{
		{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
	}

	cert := &ByocServerCertificate{
		SubjectCommonName:  "agent.example.com",
		ValidFromTimestamp: time.Now().Add(-time.Hour),
		ValidToTimestamp:   time.Now().Add(24 * time.Hour),
	}

	reg, err := NewRegistration(
		"agent-uuid", "owner-1", ansName, "", "My Agent", "desc",
		endpoints, cert, &csr, time.Now(),
	)
	require.NoError(t, err)
	return reg
}

func TestNewRegistration_Valid(t *testing.T) {
	reg := newValidRegistration(t)
	assert.Equal(t, StatusPendingValidation, reg.Status)
	assert.Equal(t, "agent-uuid", reg.AgentID)
	assert.Equal(t, "owner-1", reg.OwnerID)
	assert.Equal(t, "agent.example.com", reg.FQDN())
	assert.Len(t, reg.PendingEvents, 1)
	assert.IsType(t, AgentRegisteredEvent{}, reg.PendingEvents[0])
}

func TestNewRegistration_Validations(t *testing.T) {
	validName, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	validCSR := NewIdentityCSR("c", "x", time.Now())
	validEndpoints := []AgentEndpoint{{Protocol: ProtocolMCP, AgentURL: "https://a.b.com/"}}

	tests := []struct {
		name        string
		agentID     string
		ownerID     string
		ansName     AnsName
		displayName string
		description string
		endpoints   []AgentEndpoint
		cert        *ByocServerCertificate
		csr         *AgentCSR
		code        string
	}{
		{"missing agent id", "", "o", validName, "", "", validEndpoints, nil, &validCSR, "MISSING_AGENT_ID"},
		{"missing owner", "a", "", validName, "", "", validEndpoints, nil, &validCSR, "MISSING_OWNER_ID"},
		// AnsName empty + Identity CSR present is incoherent under §3.2.0:
		// base-only registrations cannot have an Identity Certificate
		// because the cert's URI SAN encodes the ANSName.
		{"base_only_with_csr_rejected", "a", "o", AnsName{}, "", "", validEndpoints, nil, &validCSR, "BASE_ONLY_REJECTS_IDENTITY_CSR"},
		{"display name too long", "a", "o", validName, strings.Repeat("x", 65), "", validEndpoints, nil, &validCSR, "DISPLAY_NAME_TOO_LONG"},
		{"description too long", "a", "o", validName, "", strings.Repeat("x", 151), validEndpoints, nil, &validCSR, "DESCRIPTION_TOO_LONG"},
		{"no endpoints", "a", "o", validName, "", "", nil, nil, &validCSR, "MISSING_ENDPOINTS"},
		{"missing csr (versioned)", "a", "o", validName, "", "", validEndpoints, nil, nil, "VERSIONED_REQUIRES_IDENTITY_CSR"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRegistration(tc.agentID, tc.ownerID, tc.ansName, "", tc.displayName, tc.description, tc.endpoints, tc.cert, tc.csr, time.Now())
			require.Error(t, err)
			var de *Error
			require.ErrorAs(t, err, &de)
			assert.Equal(t, tc.code, de.Code)
		})
	}
}

func TestNewRegistration_CertFQDNMismatch(t *testing.T) {
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	csr := NewIdentityCSR("c", "x", time.Now())
	ep := []AgentEndpoint{{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"}}
	cert := &ByocServerCertificate{SubjectCommonName: "other.example.com"}

	_, err := NewRegistration("a", "o", ansName, "", "", "", ep, cert, &csr, time.Now())
	assert.ErrorIs(t, err, ErrCertificate)
}

func TestAgentRegistration_Activate(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusPendingDNS
	reg.ClearEvents()

	require.NoError(t, reg.Activate(time.Now()))
	assert.Equal(t, StatusActive, reg.Status)
	assert.Len(t, reg.PendingEvents, 1)
}

func TestAgentRegistration_Activate_InvalidState(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusRevoked
	err := reg.Activate(time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestAgentRegistration_AdvanceToPendingDNS(t *testing.T) {
	reg := newValidRegistration(t)
	require.NoError(t, reg.AdvanceToPendingDNS())
	assert.Equal(t, StatusPendingDNS, reg.Status)
}

func TestAgentRegistration_AdvanceToPendingDNS_InvalidFromActive(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusActive
	err := reg.AdvanceToPendingDNS()
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestAgentRegistration_Deprecate(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusActive
	reg.ClearEvents()

	require.NoError(t, reg.Deprecate("new-agent", time.Now()))
	assert.Equal(t, StatusDeprecated, reg.Status)
	assert.Len(t, reg.PendingEvents, 1)

	// Cannot deprecate from terminal state.
	reg.Status = StatusRevoked
	assert.ErrorIs(t, reg.Deprecate("x", time.Now()), ErrInvalidState)
}

func TestAgentRegistration_Revoke(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusActive
	reg.ClearEvents()

	require.NoError(t, reg.Revoke(RevocationKeyCompromise, time.Now()))
	assert.Equal(t, StatusRevoked, reg.Status)
	assert.Len(t, reg.PendingEvents, 1)
}

func TestAgentRegistration_Revoke_InvalidReason(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusActive
	err := reg.Revoke(RevocationReason("BOGUS"), time.Now())
	assert.ErrorIs(t, err, ErrValidation)
}

func TestAgentRegistration_Revoke_FromPending(t *testing.T) {
	reg := newValidRegistration(t)
	// Pending states cannot transition directly to revoked (must use Cancel).
	err := reg.Revoke(RevocationKeyCompromise, time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestAgentRegistration_Cancel(t *testing.T) {
	reg := newValidRegistration(t)
	reg.ClearEvents()
	require.NoError(t, reg.Cancel(time.Now()))
	assert.Equal(t, StatusRevoked, reg.Status)
	assert.Len(t, reg.PendingEvents, 1)

	// Cannot cancel non-pending.
	reg.Status = StatusActive
	assert.ErrorIs(t, reg.Cancel(time.Now()), ErrInvalidState)
}

func TestAgentRegistration_Fail(t *testing.T) {
	reg := newValidRegistration(t)
	require.NoError(t, reg.Fail())
	assert.Equal(t, StatusFailed, reg.Status)

	// Cannot fail again.
	assert.ErrorIs(t, reg.Fail(), ErrInvalidState)
}

func TestAgentRegistration_Expire(t *testing.T) {
	reg := newValidRegistration(t)
	require.NoError(t, reg.Expire())
	assert.Equal(t, StatusExpired, reg.Status)

	// Cannot expire twice.
	assert.ErrorIs(t, reg.Expire(), ErrInvalidState)
}

func TestAgentRegistration_AllowsSupersede(t *testing.T) {
	reg := newValidRegistration(t)
	reg.Status = StatusActive

	assert.True(t, reg.AllowsSupersede(mustSemVer(1, 0, 1)))
	assert.True(t, reg.AllowsSupersede(mustSemVer(2, 0, 0)))
	assert.False(t, reg.AllowsSupersede(mustSemVer(1, 0, 0)))
	assert.False(t, reg.AllowsSupersede(mustSemVer(0, 9, 9)))

	reg.Status = StatusRevoked
	assert.False(t, reg.AllowsSupersede(mustSemVer(2, 0, 0)))
}

func TestAgentRegistration_ClearEvents(t *testing.T) {
	reg := newValidRegistration(t)
	events := reg.ClearEvents()
	assert.Len(t, events, 1)
	assert.Empty(t, reg.PendingEvents)
}

func TestNewRegistration_InvalidEndpoint(t *testing.T) {
	// Covers the eps.Validate() failure path in NewRegistration
	// (agent.go:127-129). The previous validation failures all
	// short-circuit before reaching endpoint validation.
	ansName, _ := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
	csr := NewIdentityCSR("c", "x", time.Now())
	// Non-empty endpoints collection with an endpoint whose host
	// doesn't match the ANS name → AgentEndpoints.Validate rejects it.
	badEndpoints := []AgentEndpoint{
		{Protocol: ProtocolMCP, AgentURL: "https://other.example.com/mcp"},
	}
	_, err := NewRegistration("a", "o", ansName, "", "", "", badEndpoints, nil, &csr, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrValidation)
}

func TestAgentRegistration_Revoke_FromTerminal(t *testing.T) {
	// Covers the r.transitionTo failure path in Revoke: a registration
	// in a terminal state (REVOKED / FAILED / EXPIRED) is not pending
	// (so skips the CANNOT_REVOKE_PENDING guard) but cannot transition
	// further, so transitionTo returns INVALID_STATUS_TRANSITION.
	for _, terminal := range []RegistrationStatus{StatusRevoked, StatusFailed, StatusExpired} {
		t.Run(string(terminal), func(t *testing.T) {
			reg := newValidRegistration(t)
			reg.Status = terminal
			err := reg.Revoke(RevocationKeyCompromise, time.Now())
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidState)
			var de *Error
			require.ErrorAs(t, err, &de)
			assert.Equal(t, "INVALID_STATUS_TRANSITION", de.Code)
		})
	}
}

func TestAgentRegistration_SubmitIdentityCSR(t *testing.T) {
	reg := newValidRegistration(t)

	t.Run("rejects when not active", func(t *testing.T) {
		// Registration starts in PENDING_VALIDATION per newValidRegistration.
		_, err := reg.SubmitIdentityCSR("csr-new", "pem", time.Now())
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidState)
		var de *Error
		require.ErrorAs(t, err, &de)
		assert.Equal(t, "AGENT_NOT_ACTIVE", de.Code)
	})

	t.Run("replaces CSR when active", func(t *testing.T) {
		reg.Status = StatusActive
		now := time.Now()
		csr, err := reg.SubmitIdentityCSR("csr-replaced", "new-pem", now)
		require.NoError(t, err)
		require.NotNil(t, csr)
		assert.Equal(t, "csr-replaced", csr.CSRID)
		assert.Equal(t, CSRTypeIdentity, csr.Type)
		assert.Equal(t, CSRStatusPending, csr.Status)
		// Aggregate state updated, too.
		require.NotNil(t, reg.IdentityCSR)
		assert.Equal(t, "csr-replaced", reg.IdentityCSR.CSRID)
	})
}

func TestAgentRegistration_SubmitServerCSR(t *testing.T) {
	// Unlike SubmitIdentityCSR, server CSRs can be submitted at any
	// state per the reference — operators may want the RA-signed path
	// before the agent is live.
	reg := newValidRegistration(t)
	now := time.Now()

	for _, status := range []RegistrationStatus{
		StatusPendingValidation,
		StatusPendingDNS,
		StatusActive,
		StatusDeprecated,
	} {
		t.Run(string(status), func(t *testing.T) {
			reg.Status = status
			csr, err := reg.SubmitServerCSR("server-csr-"+string(status), "pem", now)
			require.NoError(t, err)
			require.NotNil(t, csr)
			assert.Equal(t, CSRTypeServer, csr.Type)
			assert.Equal(t, CSRStatusPending, csr.Status)
			require.NotNil(t, reg.ServerCSR)
			assert.Equal(t, csr.CSRID, reg.ServerCSR.CSRID)
		})
	}
}

func TestRegistrationDetails_EffectiveTimestamp(t *testing.T) {
	reg := time.Now()
	d := RegistrationDetails{RegistrationTimestamp: reg}
	assert.Equal(t, reg, d.EffectiveTimestamp())

	renewed := reg.Add(time.Hour)
	d2 := d.WithRenewal(renewed)
	assert.Equal(t, renewed, d2.EffectiveTimestamp())
	// Original unchanged.
	assert.Equal(t, reg, d.EffectiveTimestamp())
}
