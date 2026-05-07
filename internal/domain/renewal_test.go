package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCSRRenewal(t *testing.T) {
	// Parallel to TestNewBYOCRenewal — validates the server-CSR
	// renewal factory that references an already-persisted CSR by ID
	// rather than carrying the cert bytes inline. Reference:
	// AgentServerCertificateRenewal with renewalType=SERVER_CSR.
	now := time.Now()
	r := NewCSRRenewal("agent-1", 42, "csr-9", "dns-tok", "http-tok", now)
	require.NotNil(t, r)
	assert.Equal(t, "agent-1", r.AgentID)
	assert.Equal(t, int64(42), r.RegistrationID)
	assert.Equal(t, RenewalTypeCSR, r.RenewalType)
	assert.Equal(t, "csr-9", r.ServerCsrID)
	// BYOC-only fields must be left empty on the CSR path.
	assert.Empty(t, r.ByocCertPEM)
	assert.Empty(t, r.ByocChainPEM)
	assert.Equal(t, ValidationPending, r.Validation.Status)
	assert.Equal(t, "dns-tok", r.Validation.DNS01ChallengeToken)
	assert.Equal(t, "http-tok", r.Validation.HTTP01ChallengeToken)
	assert.True(t, r.Validation.ExpiresAt.After(now))
	assert.Equal(t, now, r.CreatedAt)
}

func TestNewBYOCRenewal(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("agent-1", 42, "LEAF", "CHAIN", "dns-tok", "http-tok", now)
	assert.Equal(t, "agent-1", r.AgentID)
	assert.Equal(t, int64(42), r.RegistrationID)
	assert.Equal(t, RenewalTypeBYOC, r.RenewalType)
	assert.Equal(t, "LEAF", r.ByocCertPEM)
	assert.Equal(t, "CHAIN", r.ByocChainPEM)
	assert.Equal(t, ValidationPending, r.Validation.Status)
	assert.Equal(t, "dns-tok", r.Validation.DNS01ChallengeToken)
	assert.Equal(t, "http-tok", r.Validation.HTTP01ChallengeToken)
	assert.True(t, r.Validation.ExpiresAt.After(now))
}

func TestRenewalValidation_ExpiredWithoutVerification(t *testing.T) {
	now := time.Now()
	v := RenewalValidation{Status: ValidationPending, ExpiresAt: now.Add(-time.Hour)}
	assert.True(t, v.IsExpiredWithoutVerification(now))

	v.Status = ValidationVerified
	assert.False(t, v.IsExpiredWithoutVerification(now))

	v.Status = ValidationPending
	v.ExpiresAt = now.Add(time.Hour)
	assert.False(t, v.IsExpiredWithoutVerification(now))
}

func TestRenewalValidation_MarkVerified(t *testing.T) {
	v := RenewalValidation{Status: ValidationPending}
	v2, err := v.MarkVerified(time.Now())
	require.NoError(t, err)
	assert.Equal(t, ValidationVerified, v2.Status)

	_, err = v2.MarkVerified(time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestRenewalValidation_MarkFailed(t *testing.T) {
	v := RenewalValidation{Status: ValidationPending}
	v2, err := v.MarkFailed(time.Now())
	require.NoError(t, err)
	assert.Equal(t, ValidationFailed, v2.Status)

	_, err = v2.MarkFailed(time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestServerCertificateRenewal_IsExpired(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("a", 1, "c", "", "d", "h", now)
	assert.False(t, r.IsExpired(now))
	assert.True(t, r.IsExpired(now.Add(8*24*time.Hour)))
}

func TestServerCertificateRenewal_Completion(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("a", 1, "c", "", "d", "h", now)
	assert.False(t, r.IsCompleted())

	require.NoError(t, r.MarkCompleted(now.Add(time.Hour)))
	assert.True(t, r.IsCompleted())

	// Cannot complete twice.
	assert.ErrorIs(t, r.MarkCompleted(now), ErrInvalidState)
	// Cannot fail after completed.
	assert.ErrorIs(t, r.MarkFailed("x", now), ErrInvalidState)
}

func TestServerCertificateRenewal_Fail(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("a", 1, "c", "", "d", "h", now)
	require.NoError(t, r.MarkFailed("boom", now.Add(time.Second)))
	assert.Equal(t, "boom", r.FailureReason)
	assert.False(t, r.CompletedAt.IsZero())
}

func TestServerCertificateRenewal_UpdateValidationStatus(t *testing.T) {
	r := NewBYOCRenewal("a", 1, "c", "", "d", "h", time.Now())
	newV, _ := r.Validation.MarkVerified(time.Now())
	r.UpdateValidationStatus(newV)
	assert.Equal(t, ValidationVerified, r.Validation.Status)
	assert.True(t, r.IsCompleted()) // verified validation counts as completed
}
