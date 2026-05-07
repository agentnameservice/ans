package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityCSR_NewMarkSigned(t *testing.T) {
	now := time.Now()
	csr := NewIdentityCSR("csr-1", "-----CSR----", now)
	assert.Equal(t, CSRStatusPending, csr.Status)

	signed, err := csr.MarkSigned(now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, CSRStatusSigned, signed.Status)
	assert.False(t, signed.ProcessedTimestamp.IsZero())
}

func TestIdentityCSR_MarkSigned_InvalidState(t *testing.T) {
	csr := NewIdentityCSR("csr", "x", time.Now())
	signed, err := csr.MarkSigned(time.Now())
	require.NoError(t, err)

	_, err = signed.MarkSigned(time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestIdentityCSR_MarkRejected(t *testing.T) {
	csr := NewIdentityCSR("csr", "x", time.Now())
	rejected, err := csr.MarkRejected("bad key", time.Now())
	require.NoError(t, err)
	assert.Equal(t, CSRStatusRejected, rejected.Status)
	assert.Equal(t, "bad key", rejected.RejectionReason)

	_, err = rejected.MarkRejected("again", time.Now())
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestStoredCertificate_IsValid(t *testing.T) {
	now := time.Now()
	c := StoredCertificate{
		Status:              CertStatusValid,
		ExpirationTimestamp: now.Add(time.Hour),
	}
	assert.True(t, c.IsValid(now))

	c.Status = CertStatusRevoked
	assert.False(t, c.IsValid(now))

	c.Status = CertStatusValid
	c.ExpirationTimestamp = now.Add(-time.Hour)
	assert.False(t, c.IsValid(now))
}

func TestStoredCertificate_Revoke(t *testing.T) {
	c := StoredCertificate{Status: CertStatusValid}
	revoked := c.Revoke()
	assert.Equal(t, CertStatusRevoked, revoked.Status)
	// Original unchanged.
	assert.Equal(t, CertStatusValid, c.Status)
}

func TestByocServerCertificate_IsValid(t *testing.T) {
	now := time.Now()
	c := ByocServerCertificate{
		ValidFromTimestamp: now.Add(-time.Hour),
		ValidToTimestamp:   now.Add(time.Hour),
	}
	assert.True(t, c.IsValid(now))
	assert.False(t, c.IsValid(now.Add(2*time.Hour)))
	assert.False(t, c.IsValid(now.Add(-2*time.Hour)))
}

func TestByocServerCertificate_GetFullChain(t *testing.T) {
	c := ByocServerCertificate{
		LeafCertificatePEM:   "LEAF",
		ChainCertificatesPEM: "CHAIN",
	}
	assert.Equal(t, "LEAF\nCHAIN", c.GetFullChain())

	c.ChainCertificatesPEM = ""
	assert.Equal(t, "LEAF", c.GetFullChain())
}

func TestByocServerCertificate_MatchesFQDN(t *testing.T) {
	c := ByocServerCertificate{
		SubjectCommonName:       "agent.example.com",
		SubjectAlternativeNames: []string{"other.example.com", "agent.example.com"},
	}
	assert.True(t, c.MatchesFQDN("agent.example.com"))
	assert.True(t, c.MatchesFQDN("other.example.com"))
	assert.False(t, c.MatchesFQDN("nope.example.com"))
}

func TestNewServerCSR(t *testing.T) {
	now := time.Now()
	csr := NewServerCSR("srv-1", "-----BEGIN CERTIFICATE REQUEST-----...", now)
	assert.Equal(t, "srv-1", csr.CSRID)
	assert.Equal(t, CSRTypeServer, csr.Type)
	assert.Equal(t, CSRStatusPending, csr.Status)
	assert.Equal(t, now, csr.SubmissionTimestamp)

	// Server CSRs follow the same sign/reject lifecycle as identity CSRs.
	signed, err := csr.MarkSigned(now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, CSRStatusSigned, signed.Status)
}

func TestStoredCertificateFromByoc(t *testing.T) {
	// The BYOC factory projects a ByocServerCertificate into the
	// StoredCertificate shape served by GET /certificates/server so
	// downstream handlers don't need to know the provenance.
	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(90 * 24 * time.Hour)
	byoc := &ByocServerCertificate{
		LeafCertificatePEM:   "-----BEGIN CERT-----\nLEAF\n-----END CERT-----",
		ChainCertificatesPEM: "-----BEGIN CERT-----\nINTERMEDIATE\n-----END CERT-----",
		ValidFromTimestamp:   from,
		ValidToTimestamp:     to,
	}

	stored := StoredCertificateFromByoc(byoc)
	require.NotNil(t, stored)
	assert.Empty(t, stored.CSRID, "BYOC path has no CSR on our side")
	assert.Equal(t, CertTypeServer, stored.CertificateType)
	assert.Equal(t, byoc.LeafCertificatePEM, stored.CertificatePEM)
	assert.Equal(t, byoc.ChainCertificatesPEM, stored.ChainPEM)
	assert.Equal(t, CertStatusValid, stored.Status)
	assert.Equal(t, from, stored.IssueTimestamp)
	assert.Equal(t, to, stored.ExpirationTimestamp)
}
