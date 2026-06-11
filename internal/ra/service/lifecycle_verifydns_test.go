package service

// White-box table tests for verifyDNSRecords' mismatch classification.
// These pin the Fix C partition directly against the documented
// port.RecordVerification.Actual contract (port/dns.go): "first live
// answer when records exist but none matched; empty when nothing
// answered". The classification consumes that contract, so the stub
// verifier below implements it exactly — a future DNSVerifier adapter
// author who honors the documented contract gets a green test, and one
// who reintroduces the old "MISSING regardless of Actual" behavior gets
// a loud failure here rather than a silent regression at the wire.
//
// verifyDNSRecords is unexported, so this is an internal-package test
// (package service, like helpers_test.go). It builds a RegistrationService
// with only dnsVerifier wired — no store, no registry — because the
// function under test reads nothing else.

import (
	"context"
	"errors"
	"testing"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// stubDNSVerifier returns a fixed VerificationResult (and optional error)
// regardless of the expected records it is handed. Tests set results to
// the exact (Found, Actual, DNSSECVerified, Record) shapes they want to
// classify, honoring the documented Actual contract.
type stubDNSVerifier struct {
	results []port.RecordVerification
	err     error
}

func (s stubDNSVerifier) VerifyRecords(
	_ context.Context,
	_ string,
	_ []domain.ExpectedDNSRecord,
) (*port.VerificationResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &port.VerificationResult{Results: s.results}, nil
}

// rec is a tiny constructor for an ExpectedDNSRecord with the fields the
// classification cares about (Name/Type/Value/Required).
func rec(name string, typ domain.DNSRecordType, value string, required bool) domain.ExpectedDNSRecord {
	return domain.ExpectedDNSRecord{Name: name, Type: typ, Value: value, Required: required}
}

func TestVerifyDNSRecords_Classification(t *testing.T) {
	t.Parallel()

	const (
		svcbName = "agent.example.com"
		svcbVal  = "1 . alpn=mcp port=443 key65280=mcp"
		txtName  = "_ans.agent.example.com"
		txtVal   = "v=ans1; ..."
	)

	cases := []struct {
		name    string
		results []port.RecordVerification
		// want is the expected (Code, Found) pairs, in order.
		want []struct {
			code  string
			found string
		}
	}{
		{
			// Nothing answered for a present-but-absent required record:
			// MISSING, Found stays empty (no live value to surface).
			name: "absent_required_is_missing",
			results: []port.RecordVerification{
				{Record: rec(svcbName, domain.DNSRecordSVCB, svcbVal, true), Found: false, Actual: ""},
			},
			want: []struct {
				code  string
				found string
			}{{dnsCodeMissing, ""}},
		},
		{
			// Records exist but none matched: MISMATCH carrying the first
			// live answer. Pre-Fix-C this was coded MISSING and the live
			// value was dropped from the 422.
			name: "present_but_wrong_is_mismatch_carrying_live_value",
			results: []port.RecordVerification{
				{Record: rec(svcbName, domain.DNSRecordSVCB, svcbVal, true), Found: false, Actual: "wrong"},
			},
			want: []struct {
				code  string
				found string
			}{{dnsCodeMismatch, "wrong"}},
		},
		{
			// SVCB coexistence shape: the verifier's type-specific subset
			// match succeeded (Found=true) even though the live Actual
			// string differs benignly from Value (extra SvcParams from a
			// sibling family per RFC 9460 §8). Found=true is the verdict —
			// no mismatch. Pre-Fix-C the `Actual != Value` arm coded this a
			// spurious MISMATCH and defeated coexistence.
			name: "found_with_benign_actual_delta_is_ok",
			results: []port.RecordVerification{
				{Record: rec(svcbName, domain.DNSRecordSVCB, svcbVal, true), Found: true, Actual: svcbVal + " ipv4hint=192.0.2.1"},
			},
			want: nil,
		},
		{
			// The Required flag DOES gate classification. Optional records
			// in an UNSIGNED zone (no DNSSEC) are skipped whether they are
			// truly absent (Actual="") or present-but-wrong (Actual="wrong")
			// — TLSA without DNSSEC, the CNAME-at-apex HTTPS RR, and
			// union-mode SVCB rows are all Required=false by design and must
			// not 422-block the operator. Only the DNSSEC hard-fail above
			// bypasses Required (covered by the tamper cases below). Two
			// records here, both optional+unsigned, expect ZERO mismatches.
			name: "optional_unsigned_records_are_skipped",
			results: []port.RecordVerification{
				{Record: rec("_443._tcp.agent.example.com", domain.DNSRecordTLSA, "3 0 1 ab", false), Found: false, Actual: ""},
				{Record: rec(svcbName, domain.DNSRecordHTTPS, "1 . alpn=h2", false), Found: false, Actual: "wrong"},
			},
			want: nil,
		},
		{
			// DNSSEC hard-fail (untouched block): a DNSSEC-authenticated
			// SVCB response whose content disagrees is tampering — coded
			// SVCB_DNSSEC_MISMATCH, carrying the live value, regardless of
			// Required. Pins the block above the switch stays byte-identical.
			name: "dnssec_svcb_tamper_is_hardfail",
			results: []port.RecordVerification{
				{Record: rec(svcbName, domain.DNSRecordSVCB, svcbVal, false), Found: false, Actual: "tampered", DNSSECVerified: true},
			},
			want: []struct {
				code  string
				found string
			}{{"SVCB" + dnssecMismatchSuffix, "tampered"}},
		},
		{
			// DNSSEC hard-fail also fires for TLSA and HTTPS. Pin all three
			// cert/service-binding types route through the hard-fail arm.
			name: "dnssec_tlsa_and_https_tamper_are_hardfail",
			results: []port.RecordVerification{
				{Record: rec("_443._tcp.agent.example.com", domain.DNSRecordTLSA, "3 0 1 ab", false), Found: false, Actual: "3 0 1 cd", DNSSECVerified: true},
				{Record: rec(svcbName, domain.DNSRecordHTTPS, "1 . alpn=h2", false), Found: false, Actual: "1 . alpn=h3", DNSSECVerified: true},
			},
			want: []struct {
				code  string
				found string
			}{
				{"TLSA" + dnssecMismatchSuffix, "3 0 1 cd"},
				{"HTTPS" + dnssecMismatchSuffix, "1 . alpn=h3"},
			},
		},
		{
			// TXT carries no cryptographic commitment, so a
			// DNSSEC-authenticated TXT mismatch is NOT a hard fail — it
			// falls through to the standard classification. Here the TXT
			// record is absent (Found=false, Actual="") → MISSING, the same
			// verdict a non-DNSSEC absent record gets.
			name: "dnssec_txt_falls_through_to_missing",
			results: []port.RecordVerification{
				{Record: rec(txtName, domain.DNSRecordTXT, txtVal, true), Found: false, Actual: "", DNSSECVerified: true},
			},
			want: []struct {
				code  string
				found string
			}{{dnsCodeMissing, ""}},
		},
		{
			// TXT DNSSEC mismatch with a live wrong value falls through to
			// the standard classification too: present-but-wrong → MISMATCH
			// carrying the live value.
			name: "dnssec_txt_present_but_wrong_falls_through_to_mismatch",
			results: []port.RecordVerification{
				{Record: rec(txtName, domain.DNSRecordTXT, txtVal, true), Found: false, Actual: "v=ans1; stale", DNSSECVerified: true},
			},
			want: []struct {
				code  string
				found string
			}{{dnsCodeMismatch, "v=ans1; stale"}},
		},
		{
			// Mixed batch: one absent (MISSING), one present-but-wrong
			// (MISMATCH carrying live), one satisfied subset (Found=true,
			// no mismatch). Order is preserved.
			name: "mixed_batch_preserves_order_and_partitions",
			results: []port.RecordVerification{
				{Record: rec("a.example.com", domain.DNSRecordSVCB, "v1", true), Found: false, Actual: ""},
				{Record: rec("b.example.com", domain.DNSRecordSVCB, "v2", true), Found: false, Actual: "live2"},
				{Record: rec("c.example.com", domain.DNSRecordSVCB, "v3", true), Found: true, Actual: "v3 extra"},
			},
			want: []struct {
				code  string
				found string
			}{
				{dnsCodeMissing, ""},
				{dnsCodeMismatch, "live2"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := &RegistrationService{dnsVerifier: stubDNSVerifier{results: tc.results}}
			got, perRecord, err := svc.verifyDNSRecords(context.Background(), "agent.example.com", nil)
			if err != nil {
				t.Fatalf("verifyDNSRecords: unexpected error %v", err)
			}
			// perRecord must echo the verifier's full result set so the
			// attestation builder sees every record (matched or not).
			if len(perRecord) != len(tc.results) {
				t.Errorf("perRecord len: got %d want %d", len(perRecord), len(tc.results))
			}
			if len(got) != len(tc.want) {
				t.Fatalf("mismatch count: got %d want %d (%+v)", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				if got[i].Code != w.code {
					t.Errorf("mismatch[%d] Code: got %q want %q", i, got[i].Code, w.code)
				}
				if got[i].Found != w.found {
					t.Errorf("mismatch[%d] Found: got %q want %q", i, got[i].Found, w.found)
				}
			}
		})
	}
}

// TestVerifyDNSRecords_VerifierErrorIsReturned pins the WARN-path
// contract: when the underlying verifier returns a systemic error,
// verifyDNSRecords surfaces it (no panic, no swallow) so VerifyDNS can
// log a WARN and map it to a 500. The error value must propagate
// unchanged.
func TestVerifyDNSRecords_VerifierErrorIsReturned(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("dns unreachable")
	svc := &RegistrationService{dnsVerifier: stubDNSVerifier{err: sentinel}}
	out, perRecord, err := svc.verifyDNSRecords(context.Background(), "agent.example.com", nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error: got %v want %v", err, sentinel)
	}
	if out != nil || perRecord != nil {
		t.Errorf("on error want nil slices, got out=%v perRecord=%v", out, perRecord)
	}
}

// TestVerifyDNSRecords_NilVerifierSkips pins the local-dev escape hatch:
// a nil dnsVerifier short-circuits to "DNS correct" (no mismatches, no
// error). Untouched by Fix C but exercised here so the early return
// stays covered alongside the classification.
func TestVerifyDNSRecords_NilVerifierSkips(t *testing.T) {
	t.Parallel()
	svc := &RegistrationService{} // dnsVerifier nil
	out, perRecord, err := svc.verifyDNSRecords(context.Background(), "agent.example.com",
		[]domain.ExpectedDNSRecord{rec("a", domain.DNSRecordSVCB, "v", true)})
	if err != nil || out != nil || perRecord != nil {
		t.Fatalf("nil verifier: want all-nil, got out=%v perRecord=%v err=%v", out, perRecord, err)
	}
}
