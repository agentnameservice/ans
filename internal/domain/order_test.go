package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeType_IsValid(t *testing.T) {
	assert.True(t, ChallengeTypeDNS01.IsValid())
	assert.True(t, ChallengeTypeHTTP01.IsValid())
	assert.False(t, ChallengeType("TLS_ALPN_01").IsValid())
	assert.False(t, ChallengeType("").IsValid())
}

func TestChallenge_EffectiveDNSRecordName(t *testing.T) {
	// RFC 8555 default when the provider didn't override.
	c := Challenge{Type: ChallengeTypeDNS01, Token: "tok"}
	assert.Equal(t, "_acme-challenge.agent.example.com", c.EffectiveDNSRecordName("agent.example.com"))

	// Provider override (proprietary DV record names) wins.
	c.DNSRecordName = "_dnsauth.agent.example.com"
	assert.Equal(t, "_dnsauth.agent.example.com", c.EffectiveDNSRecordName("agent.example.com"))
}

func TestChallenge_EffectiveDNSRecordValue(t *testing.T) {
	// Self-issued: raw token.
	c := Challenge{Type: ChallengeTypeDNS01, Token: "tok"}
	assert.Equal(t, "tok", c.EffectiveDNSRecordValue())

	// ACME providers publish the key-authorization digest instead.
	c.DNSRecordValue = "digest-of-keyauth"
	assert.Equal(t, "digest-of-keyauth", c.EffectiveDNSRecordValue())
}

func TestChallenge_EffectiveHTTPPath(t *testing.T) {
	c := Challenge{Type: ChallengeTypeHTTP01, Token: "tok"}
	assert.Equal(t, "/.well-known/acme-challenge/tok", c.EffectiveHTTPPath())

	c.HTTPPath = "/.well-known/pki-validation/provider.html"
	assert.Equal(t, "/.well-known/pki-validation/provider.html", c.EffectiveHTTPPath())
}

func TestChallenge_ExpectedHTTPContent(t *testing.T) {
	// Self-issued: raw token (no account binding).
	c := Challenge{Type: ChallengeTypeHTTP01, Token: "tok"}
	assert.Equal(t, "tok", c.ExpectedHTTPContent())

	// Account-bound (ACME): the key authorization.
	c.KeyAuthorization = "tok.thumbprint"
	assert.Equal(t, "tok.thumbprint", c.ExpectedHTTPContent())
}

func TestNewSelfIssuedOrder(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	o := NewSelfIssuedOrder("dns-tok", "http-tok", exp)
	assert.Equal(t, OrderStatePending, o.State)
	assert.Empty(t, o.OrderRef)
	assert.Equal(t, exp, o.ExpiresAt)
	assert.False(t, o.IsZero())

	dns01, ok := o.ChallengeOfType(ChallengeTypeDNS01)
	require.True(t, ok)
	assert.Equal(t, "dns-tok", dns01.Token)
	assert.Empty(t, dns01.KeyAuthorization)

	http01, ok := o.ChallengeOfType(ChallengeTypeHTTP01)
	require.True(t, ok)
	assert.Equal(t, "http-tok", http01.Token)
}

func TestCertificateOrder_IsZero(t *testing.T) {
	for _, tc := range []struct {
		order CertificateOrder
		want  bool
	}{
		{CertificateOrder{}, true},
		{CertificateOrder{OrderRef: "ref"}, false},
		{CertificateOrder{State: OrderStatePending}, false},
		{CertificateOrder{Challenges: []Challenge{{}}}, false},
		{CertificateOrder{ExpiresAt: time.Now()}, false},
	} {
		assert.Equal(t, tc.want, tc.order.IsZero(), "%+v", tc.order)
	}
}

func TestCertificateOrder_ChallengeOfType_Missing(t *testing.T) {
	o := CertificateOrder{Challenges: []Challenge{{Type: ChallengeTypeDNS01, Token: "t"}}}
	_, ok := o.ChallengeOfType(ChallengeTypeHTTP01)
	assert.False(t, ok)
}

func TestCertificateOrder_IsExpired(t *testing.T) {
	now := time.Now()

	// Zero expiry never expires (legacy rows).
	zero := CertificateOrder{State: OrderStatePending}
	assert.False(t, zero.IsExpired(now))

	// Past expiry while non-terminal → expired.
	past := CertificateOrder{State: OrderStatePending, ExpiresAt: now.Add(-time.Minute)}
	assert.True(t, past.IsExpired(now))

	// Future expiry → not expired.
	future := CertificateOrder{State: OrderStatePending, ExpiresAt: now.Add(time.Minute)}
	assert.False(t, future.IsExpired(now))

	// Terminal states never report expired — the order resolved
	// before the window closed.
	done := CertificateOrder{State: OrderStateCompleted, ExpiresAt: now.Add(-time.Minute)}
	assert.False(t, done.IsExpired(now))
	failed := CertificateOrder{State: OrderStateFailed, ExpiresAt: now.Add(-time.Minute)}
	assert.False(t, failed.IsExpired(now))
}

func TestCertificateOrder_MarkIssuing(t *testing.T) {
	o := NewSelfIssuedOrder("d", "h", time.Now().Add(time.Hour))
	require.NoError(t, o.MarkIssuing())
	assert.Equal(t, OrderStateIssuing, o.State)

	// Idempotent for re-driven verify-acme calls.
	require.NoError(t, o.MarkIssuing())
	assert.Equal(t, OrderStateIssuing, o.State)

	// COMPLETED → ISSUING is invalid.
	done := CertificateOrder{State: OrderStateCompleted}
	assert.ErrorIs(t, done.MarkIssuing(), ErrInvalidState)
}

func TestCertificateOrder_MarkCompleted(t *testing.T) {
	// From PENDING (synchronous issuers / BYOC validation).
	o := NewSelfIssuedOrder("d", "h", time.Now().Add(time.Hour))
	require.NoError(t, o.MarkCompleted())
	assert.Equal(t, OrderStateCompleted, o.State)

	// From ISSUING (re-driven async finalize).
	o2 := CertificateOrder{State: OrderStateIssuing}
	require.NoError(t, o2.MarkCompleted())
	assert.Equal(t, OrderStateCompleted, o2.State)

	// Terminal → COMPLETED is invalid.
	assert.ErrorIs(t, o.MarkCompleted(), ErrInvalidState)
	failed := CertificateOrder{State: OrderStateFailed}
	assert.ErrorIs(t, failed.MarkCompleted(), ErrInvalidState)
}

func TestCertificateOrder_MarkFailed(t *testing.T) {
	o := NewSelfIssuedOrder("d", "h", time.Now().Add(time.Hour))
	require.NoError(t, o.MarkFailed())
	assert.Equal(t, OrderStateFailed, o.State)

	o2 := CertificateOrder{State: OrderStateIssuing}
	require.NoError(t, o2.MarkFailed())
	assert.Equal(t, OrderStateFailed, o2.State)

	// Terminal → FAILED is invalid.
	assert.ErrorIs(t, o.MarkFailed(), ErrInvalidState)
	done := CertificateOrder{State: OrderStateCompleted}
	assert.ErrorIs(t, done.MarkFailed(), ErrInvalidState)
}

func TestRenewalValidation_ChallengeOfType(t *testing.T) {
	v := RenewalValidation{Challenges: []Challenge{
		{Type: ChallengeTypeDNS01, Token: "d"},
		{Type: ChallengeTypeHTTP01, Token: "h"},
	}}
	dns01, ok := v.ChallengeOfType(ChallengeTypeDNS01)
	require.True(t, ok)
	assert.Equal(t, "d", dns01.Token)
	var empty RenewalValidation
	_, ok = empty.ChallengeOfType(ChallengeTypeDNS01)
	assert.False(t, ok)
}

func TestTLSARecordForCert(t *testing.T) {
	rec := TLSARecordForCert("agent.example.com", "abc123")
	assert.Equal(t, "_443._tcp.agent.example.com", rec.Name)
	assert.Equal(t, DNSRecordTLSA, rec.Type)
	assert.Equal(t, "3 1 1 abc123", rec.Value)
	assert.Equal(t, PurposeCertificateBinding, rec.Purpose)
	assert.False(t, rec.Required)
}

// TestNewRenewalValidation_ClampsToOrderExpiry pins the window
// clamping: when the provider's order outlives the standard renewal
// window the renewal keeps its own deadline, and when the order ends
// first the validation honors the order's expiry.
func TestNewRenewalValidation_ClampsToOrderExpiry(t *testing.T) {
	now := time.Now()

	// Order expires after the 7d renewal window → renewal window wins.
	longOrder := NewSelfIssuedOrder("d", "h", now.Add(30*24*time.Hour))
	r := NewCSRRenewal("a", 1, "csr", longOrder, now)
	assert.Equal(t, now.Add(renewalExpiryDuration), r.Validation.ExpiresAt)

	// Zero order expiry → renewal window.
	zeroOrder := CertificateOrder{State: OrderStatePending}
	r2 := NewCSRRenewal("a", 1, "csr", zeroOrder, now)
	assert.Equal(t, now.Add(renewalExpiryDuration), r2.Validation.ExpiresAt)

	// Order expires before the window → clamped to the order.
	shortOrder := NewSelfIssuedOrder("d", "h", now.Add(time.Hour))
	r3 := NewCSRRenewal("a", 1, "csr", shortOrder, now)
	assert.Equal(t, now.Add(time.Hour), r3.Validation.ExpiresAt)
	assert.Empty(t, r3.Validation.OrderRef)
}
