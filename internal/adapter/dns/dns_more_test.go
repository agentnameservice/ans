package dns

import (
	"context"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// TestLookupVerifier_TLSA_Mismatch covers the "mismatch records
// r.Actual but not r.Found" branch in verifyTLSA — pre-coverage we
// only saw the Match path.
func TestLookupVerifier_TLSA_Mismatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.add("_443._tcp.agent.example.com.", "TLSA",
		`_443._tcp.agent.example.com. 3600 IN TLSA 3 1 1 e31701de748c6339aa403571c2052d715d5fe83dbec9906611fbc430965c0133`)

	recs := []domain.ExpectedDNSRecord{{
		Name: "_443._tcp.agent.example.com", Type: domain.DNSRecordTLSA,
		Value:    "3 1 1 0000000000000000000000000000000000000000000000000000000000000000",
		Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if got[0].found {
		t.Error("mismatched TLSA must not be Found")
	}
	if got[0].actual == "" {
		t.Error("mismatched TLSA should still surface r.Actual for debugging")
	}
}

// TestLookupVerifier_HTTPS_Mismatch — same as TLSA but for HTTPS.
func TestLookupVerifier_HTTPS_Mismatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.add("agent.example.com.", "HTTPS",
		`agent.example.com. 3600 IN HTTPS 1 . alpn="h2"`)

	recs := []domain.ExpectedDNSRecord{{
		Name: "agent.example.com", Type: domain.DNSRecordHTTPS,
		Value:    `99 different.example. alpn=h3`, // intentionally different
		Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if got[0].found {
		t.Error("mismatched HTTPS must not be Found")
	}
	if got[0].actual == "" {
		t.Error("mismatched HTTPS should still surface r.Actual")
	}
}

// TestLookupVerifier_HTTPS_NXDOMAIN — server returns no records
// → NXDOMAIN → r.Error populated with "rcode NXDOMAIN".
func TestLookupVerifier_HTTPS_NXDOMAIN(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	recs := []domain.ExpectedDNSRecord{{
		Name: "missing.agent.example.com", Type: domain.DNSRecordHTTPS,
		Value: "1 . alpn=h2", Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if got[0].found {
		t.Error("NXDOMAIN HTTPS must not be Found")
	}
	if got[0].errString == "" {
		t.Error("expected error to be populated for NXDOMAIN HTTPS")
	}
}

// TestLookupVerifier_TLSA_NXDOMAIN — same as above for TLSA.
func TestLookupVerifier_TLSA_NXDOMAIN(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	recs := []domain.ExpectedDNSRecord{{
		Name: "_443._tcp.missing.agent.example.com", Type: domain.DNSRecordTLSA,
		Value: "3 1 1 abcdef", Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if got[0].found {
		t.Error("NXDOMAIN TLSA must not be Found")
	}
}

// TestLookupVerifier_TXTServerUnreachable_SurfacesError — point the
// verifier at an unreachable address with a small timeout to drive
// the exchange failure path in verifyTXT.
func TestLookupVerifier_TXTServerUnreachable_SurfacesError(t *testing.T) {
	t.Parallel()
	v := NewLookupVerifier(WithServer("127.0.0.1:1"), WithTimeout(50*time.Millisecond))
	recs := []domain.ExpectedDNSRecord{{
		Name: "agent.example.com", Type: domain.DNSRecordTXT,
		Value: "anything", Required: true,
	}}
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", recs)
	if err != nil {
		t.Fatalf("VerifyRecords: %v", err)
	}
	if got.Results[0].Found {
		t.Error("unreachable server must not yield Found=true")
	}
	if got.Results[0].Error == "" {
		t.Error("unreachable server should surface a transport error")
	}
}

// TestLookupVerifier_TLSA_ServerUnreachable parallels the TXT case
// for the verifyTLSA error branch.
func TestLookupVerifier_TLSA_ServerUnreachable(t *testing.T) {
	t.Parallel()
	v := NewLookupVerifier(WithServer("127.0.0.1:1"), WithTimeout(50*time.Millisecond))
	recs := []domain.ExpectedDNSRecord{{
		Name: "_443._tcp.agent.example.com", Type: domain.DNSRecordTLSA,
		Value: "3 1 1 abcdef", Required: true,
	}}
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", recs)
	if err != nil {
		t.Fatalf("VerifyRecords: %v", err)
	}
	if got.Results[0].Error == "" {
		t.Error("unreachable server should surface a transport error for TLSA")
	}
}

// TestLookupVerifier_HTTPS_ServerUnreachable parallels for HTTPS.
func TestLookupVerifier_HTTPS_ServerUnreachable(t *testing.T) {
	t.Parallel()
	v := NewLookupVerifier(WithServer("127.0.0.1:1"), WithTimeout(50*time.Millisecond))
	recs := []domain.ExpectedDNSRecord{{
		Name: "agent.example.com", Type: domain.DNSRecordHTTPS,
		Value: "1 . alpn=h2", Required: true,
	}}
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", recs)
	if err != nil {
		t.Fatalf("VerifyRecords: %v", err)
	}
	if got.Results[0].Error == "" {
		t.Error("unreachable server should surface a transport error for HTTPS")
	}
}
