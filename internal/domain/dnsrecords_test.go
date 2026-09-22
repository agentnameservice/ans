package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidDiscoveryProfiles pins the canonical valid set of
// DiscoveryProfile values returned by the helper used in the V2
// INVALID_DISCOVERY_PROFILE error message and (eventually) by spec
// generation tooling. Order and contents are stable so an external
// client's error-message fixtures can match.
func TestValidDiscoveryProfiles(t *testing.T) {
	got := ValidDiscoveryProfiles()
	want := []string{"ANS_DNSAID", "ANS_TXT"}
	assert.Equal(t, want, got)
}

// TestDefaultDiscoveryProfiles pins the default set applied when a V2
// register request omits discoveryProfiles. Pinned to the DNS-AID
// SVCB family {ANS_DNSAID}; operators with legacy `_ans` zone tooling
// opt into ANS_TXT explicitly.
func TestDefaultDiscoveryProfiles(t *testing.T) {
	got := DefaultDiscoveryProfiles()
	want := []DiscoveryProfile{DiscoveryProfileANSDNSAID}
	assert.Equal(t, want, got)
}

// TestDiscoveryProfile_IsValid covers the typed-enum membership predicate
// applyDiscoveryProfiles and the registry-coherence check both rely on.
func TestDiscoveryProfile_IsValid(t *testing.T) {
	tests := []struct {
		name string
		s    DiscoveryProfile
		want bool
	}{
		{name: "ans_dnsaid_is_valid", s: DiscoveryProfileANSDNSAID, want: true},
		{name: "ans_txt_is_valid", s: DiscoveryProfileANSTXT, want: true},
		{name: "empty_is_invalid", s: DiscoveryProfile(""), want: false},
		{name: "unknown_is_invalid", s: DiscoveryProfile("UNKNOWN_FAMILY"), want: false},
		{name: "lowercase_is_invalid", s: DiscoveryProfile("ans_dnsaid"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.IsValid())
		})
	}
}

// tlsaTestCert mints a self-signed P-256 certificate for use in TLSA
// tests. Returns the parsed cert so callers can inspect RawSubjectPublicKeyInfo.
func tlsaTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"agent.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestTLSARecordForCertSPKI_HashMatchesSPKI verifies that
// TLSARecordForCertSPKI emits `3 1 1 <hash>` where hash is the
// SHA-256 of the certificate's SubjectPublicKeyInfo DER bytes — NOT
// the full-certificate hash that TLSARecordForCert uses.
//
// This is the critical DANE selector-1 invariant: the record value
// must equal hex(SHA-256(cert.RawSubjectPublicKeyInfo)) so a relying
// party performing DANE-EE validation against a live TLS handshake
// can compute the same hash from the presented certificate's SPKI
// and find a match.
func TestTLSARecordForCertSPKI_HashMatchesSPKI(t *testing.T) {
	cert := tlsaTestCert(t)
	fqdn := "agent.example.com"

	// Ground-truth: SHA-256 of the SPKI DER (selector 1, matching-type 1).
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	wantHex := hex.EncodeToString(spkiSum[:])

	rec := TLSARecordForCertSPKI(fqdn, wantHex)

	assert.Equal(t, "_443._tcp.agent.example.com", rec.Name)
	assert.Equal(t, DNSRecordTLSA, rec.Type)
	assert.Equal(t, "3 1 1 "+wantHex, rec.Value, "TLSA value must be '3 1 1 <sha256(SPKI)>'")
	assert.Equal(t, PurposeCertificateBinding, rec.Purpose)
	assert.False(t, rec.Required)
	assert.Equal(t, 3600, rec.TTL)
}

// TestTLSARecordForCertSPKI_DiffersFromFullCertHash guards the
// correctness trap: selector 1 (SPKI) and selector 0 (full cert)
// produce different hashes for the same certificate. Emitting `3 1 1`
// with the full-cert SHA-256 would create a record that no conformant
// DANE implementation matches.
func TestTLSARecordForCertSPKI_DiffersFromFullCertHash(t *testing.T) {
	cert := tlsaTestCert(t)

	fullCertSum := sha256.Sum256(cert.Raw)
	fullCertHex := hex.EncodeToString(fullCertSum[:])

	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiSum[:])

	// The two fingerprints must differ — if they were equal we would
	// have the same cert encoding as its SPKI encoding, which is never
	// true for a real X.509 certificate.
	assert.NotEqual(t, fullCertHex, spkiHex,
		"SPKI fingerprint must differ from full-cert fingerprint")

	spkiRec := TLSARecordForCertSPKI("agent.example.com", spkiHex)
	certRec := TLSARecordForCert("agent.example.com", fullCertHex)

	assert.NotEqual(t, spkiRec.Value, certRec.Value,
		"3 1 1 record value must differ from 3 0 1 record value for the same cert")
}
