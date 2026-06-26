package service_test

import (
	"testing"

	"github.com/godaddy/ans/internal/ra/service"
)

// TestDNSMismatch_Classification pins the wire-code → predicate mapping
// the RA's 422 mappers depend on. verifyDNSRecords emits MISSING,
// MISMATCH, or a per-record-type "<RECORD_TYPE>_DNSSEC_MISMATCH" code;
// IsMissing and IsIncorrect partition those so missingRecords and
// incorrectRecords stay complete. Codes are pinned as literals (not the
// unexported constants) so this also guards the wire contract — a TLSA-,
// SVCB-, or HTTPS-DNSSEC tampering code MUST classify as incorrect.
func TestDNSMismatch_Classification(t *testing.T) {
	cases := []struct {
		name          string
		code          string
		wantMissing   bool
		wantIncorrect bool
	}{
		{"missing", "MISSING", true, false},
		{"plain_mismatch", "MISMATCH", false, true},
		{"tlsa_dnssec", "TLSA_DNSSEC_MISMATCH", false, true},
		{"svcb_dnssec", "SVCB_DNSSEC_MISMATCH", false, true},
		{"https_dnssec", "HTTPS_DNSSEC_MISMATCH", false, true},
		{"unknown_code_is_neither", "SOMETHING_ELSE", false, false},
		{"empty_code_is_neither", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := service.DNSMismatch{Code: tc.code}
			if got := m.IsMissing(); got != tc.wantMissing {
				t.Errorf("IsMissing(%q) = %v, want %v", tc.code, got, tc.wantMissing)
			}
			if got := m.IsIncorrect(); got != tc.wantIncorrect {
				t.Errorf("IsIncorrect(%q) = %v, want %v", tc.code, got, tc.wantIncorrect)
			}
		})
	}
}
