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
	r := NewCSRRenewal("agent-1", 42, "csr-9",
		NewSelfIssuedOrder("dns-tok", "http-tok", now.Add(24*time.Hour)), now)
	require.NotNil(t, r)
	assert.Equal(t, "agent-1", r.AgentID)
	assert.Equal(t, int64(42), r.RegistrationID)
	assert.Equal(t, RenewalTypeCSR, r.RenewalType)
	assert.Equal(t, "csr-9", r.ServerCsrID)
	// BYOC-only fields must be left empty on the CSR path.
	assert.Empty(t, r.ByocCertPEM)
	assert.Empty(t, r.ByocChainPEM)
	assert.Equal(t, ValidationPending, r.Validation.Status)
	dns01, ok := r.Validation.ChallengeOfType(ChallengeTypeDNS01)
	require.True(t, ok)
	assert.Equal(t, "dns-tok", dns01.Token)
	http01, ok := r.Validation.ChallengeOfType(ChallengeTypeHTTP01)
	require.True(t, ok)
	assert.Equal(t, "http-tok", http01.Token)
	// The validation window clamps to the order expiry when the
	// order ends before the standard renewal window.
	assert.Equal(t, now.Add(24*time.Hour), r.Validation.ExpiresAt)
	assert.Equal(t, now, r.CreatedAt)
}

func TestNewBYOCRenewal(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("agent-1", 42, "LEAF", "CHAIN",
		NewSelfIssuedOrder("dns-tok", "http-tok", now.Add(24*time.Hour)), now)
	assert.Equal(t, "agent-1", r.AgentID)
	assert.Equal(t, int64(42), r.RegistrationID)
	assert.Equal(t, RenewalTypeBYOC, r.RenewalType)
	assert.Equal(t, "LEAF", r.ByocCertPEM)
	assert.Equal(t, "CHAIN", r.ByocChainPEM)
	assert.Equal(t, ValidationPending, r.Validation.Status)
	dns01, ok := r.Validation.ChallengeOfType(ChallengeTypeDNS01)
	require.True(t, ok)
	assert.Equal(t, "dns-tok", dns01.Token)
	http01, ok := r.Validation.ChallengeOfType(ChallengeTypeHTTP01)
	require.True(t, ok)
	assert.Equal(t, "http-tok", http01.Token)
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
	r := NewBYOCRenewal("a", 1, "c", "", NewSelfIssuedOrder("d", "h", now.Add(30*24*time.Hour)), now)
	assert.False(t, r.IsExpired(now))
	assert.True(t, r.IsExpired(now.Add(8*24*time.Hour)))
}

func TestServerCertificateRenewal_Completion(t *testing.T) {
	now := time.Now()
	r := NewBYOCRenewal("a", 1, "c", "", NewSelfIssuedOrder("d", "h", now.Add(30*24*time.Hour)), now)
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
	r := NewBYOCRenewal("a", 1, "c", "", NewSelfIssuedOrder("d", "h", now.Add(30*24*time.Hour)), now)
	require.NoError(t, r.MarkFailed("boom", now.Add(time.Second)))
	assert.Equal(t, "boom", r.FailureReason)
	assert.False(t, r.CompletedAt.IsZero())
}

func TestServerCertificateRenewal_UpdateValidationStatus(t *testing.T) {
	r := NewBYOCRenewal("a", 1, "c", "", NewSelfIssuedOrder("d", "h", time.Now().Add(30*24*time.Hour)), time.Now())
	newV, _ := r.Validation.MarkVerified(time.Now())
	r.UpdateValidationStatus(newV)
	assert.Equal(t, ValidationVerified, r.Validation.Status)
	// Verified validation alone is NOT completion: a CSR renewal whose
	// order is still ISSUING is verified-but-incomplete until
	// MarkCompleted runs.
	assert.False(t, r.IsCompleted())
	require.NoError(t, r.MarkCompleted(time.Now()))
	assert.True(t, r.IsCompleted())
}
