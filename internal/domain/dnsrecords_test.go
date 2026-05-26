package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidDNSRecordStyles pins the canonical valid set of
// DNSRecordStyle values returned by the helper used in the V2
// INVALID_DNS_RECORD_STYLE error message and (eventually) by spec
// generation tooling. Order and contents are stable so an external
// client's error-message fixtures can match.
func TestValidDNSRecordStyles(t *testing.T) {
	got := ValidDNSRecordStyles()
	want := []string{"ANS_SVCB", "ANS_TXT"}
	assert.Equal(t, want, got)
}

// TestDefaultDNSRecordStyles pins the default set applied when a V2
// register request omits dnsRecordStyles. {ANS_SVCB} per §4.4.2.
func TestDefaultDNSRecordStyles(t *testing.T) {
	got := DefaultDNSRecordStyles()
	want := []DNSRecordStyle{DNSRecordStyleSVCB}
	assert.Equal(t, want, got)
}

// TestDNSRecordStyle_IsValid covers the typed-enum membership predicate
// applyDNSRecordStyles and the registry-coherence check both rely on.
func TestDNSRecordStyle_IsValid(t *testing.T) {
	tests := []struct {
		name string
		s    DNSRecordStyle
		want bool
	}{
		{name: "ans_svcb_is_valid", s: DNSRecordStyleSVCB, want: true},
		{name: "ans_txt_is_valid", s: DNSRecordStyleTXT, want: true},
		{name: "empty_is_invalid", s: DNSRecordStyle(""), want: false},
		{name: "unknown_is_invalid", s: DNSRecordStyle("UNKNOWN_FAMILY"), want: false},
		{name: "lowercase_is_invalid", s: DNSRecordStyle("ans_svcb"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.s.IsValid())
		})
	}
}
