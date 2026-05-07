package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistrationStatus_IsValid(t *testing.T) {
	valid := []RegistrationStatus{
		StatusPendingValidation, StatusPendingDNS,
		StatusActive, StatusDeprecated, StatusRevoked, StatusFailed, StatusExpired,
	}
	for _, s := range valid {
		assert.True(t, s.IsValid(), "expected %s to be valid", s)
	}
	assert.False(t, RegistrationStatus("BOGUS").IsValid())
	assert.False(t, RegistrationStatus("").IsValid())
}

func TestRegistrationStatus_IsPending(t *testing.T) {
	pending := []RegistrationStatus{StatusPendingValidation, StatusPendingDNS}
	for _, s := range pending {
		assert.True(t, s.IsPending(), "expected %s pending", s)
	}
	assert.False(t, StatusActive.IsPending())
	assert.False(t, StatusRevoked.IsPending())
}

func TestRegistrationStatus_IsTerminal(t *testing.T) {
	terminal := []RegistrationStatus{StatusRevoked, StatusFailed, StatusExpired}
	for _, s := range terminal {
		assert.True(t, s.IsTerminal(), "expected %s terminal", s)
	}
	assert.False(t, StatusActive.IsTerminal())
	assert.False(t, StatusPendingValidation.IsTerminal())
	assert.False(t, StatusDeprecated.IsTerminal())
}

func TestRegistrationStatus_String(t *testing.T) {
	assert.Equal(t, "ACTIVE", StatusActive.String())
}

func TestRegistrationStatus_CanTransitionTo(t *testing.T) {
	t.Run("valid transitions", func(t *testing.T) {
		// V2 lifecycle: PENDING_VALIDATION → PENDING_DNS → ACTIVE,
		// with early-failure edges from either pending state. Matches
		// spec/api-spec-v2.yaml AgentLifecycleStatus and the reference
		// RA's RegistrationStatus enum.
		assert.True(t, StatusPendingValidation.CanTransitionTo(StatusPendingDNS))
		assert.True(t, StatusPendingDNS.CanTransitionTo(StatusActive))
		assert.True(t, StatusActive.CanTransitionTo(StatusDeprecated))
		assert.True(t, StatusActive.CanTransitionTo(StatusRevoked))
		assert.True(t, StatusDeprecated.CanTransitionTo(StatusRevoked))
		// Early-failure edges from each pending state.
		assert.True(t, StatusPendingValidation.CanTransitionTo(StatusFailed))
		assert.True(t, StatusPendingValidation.CanTransitionTo(StatusRevoked))
		assert.True(t, StatusPendingDNS.CanTransitionTo(StatusFailed))
	})

	t.Run("invalid transitions", func(t *testing.T) {
		assert.False(t, StatusActive.CanTransitionTo(StatusPendingValidation))
		assert.False(t, StatusRevoked.CanTransitionTo(StatusActive))
		assert.False(t, StatusFailed.CanTransitionTo(StatusActive))
		// Activation is not reachable directly from PENDING_VALIDATION.
		assert.False(t, StatusPendingValidation.CanTransitionTo(StatusActive))
	})

	t.Run("unknown status cannot transition", func(t *testing.T) {
		assert.False(t, RegistrationStatus("UNKNOWN").CanTransitionTo(StatusActive))
	})
}

func TestRegistrationStatus_ValidateTransition(t *testing.T) {
	assert.NoError(t, StatusActive.ValidateTransition(StatusDeprecated))
	err := StatusActive.ValidateTransition(StatusPendingValidation)
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestRevocationReason_IsValid(t *testing.T) {
	valid := []RevocationReason{
		RevocationKeyCompromise, RevocationCessationOfOperation,
		RevocationAffiliationChanged, RevocationSuperseded,
		RevocationCertificateHold, RevocationPrivilegeWithdrawn,
		RevocationAACompromise,
	}
	for _, r := range valid {
		assert.True(t, r.IsValid(), "expected %s valid", r)
	}
	assert.False(t, RevocationReason("").IsValid())
	assert.False(t, RevocationReason("BOGUS").IsValid())
}

func TestRevocationReason_String(t *testing.T) {
	assert.Equal(t, "KEY_COMPROMISE", RevocationKeyCompromise.String())
}
