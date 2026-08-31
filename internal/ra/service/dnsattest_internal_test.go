package service

// White-box tests for attestedDNSRecords, the filter that decides what
// `dnsRecordsProvisioned[]` claims in the AGENT_REGISTERED leaf.
//
// The leaf is signed and appended to a log nobody can amend, so the
// invariant these tests defend is one-directional: a record may only
// appear in the attestation if a verification result said it was found.
// Every case below is a shape the real lookup verifier produces.
//
// attestedDNSRecords is unexported, so this is an internal-package test.
// It reuses rec() from lifecycle_verifydns_test.go.

import (
	"strings"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// verified pairs an expected record with the verifier's verdict, mirroring
// what the lookup adapter returns: the same Record struct it was handed,
// plus Found. With found=false, Actual and Error both stay empty, which is
// the MISSING shape — the adapter produces it for both NXDOMAIN (the name
// does not exist, which is what declining an optional record looks like)
// and NODATA (the name exists with no records of this type). See
// TestDropCauseMatchesLookupAdapterShapes for why those two must not carry
// an Error.
func verified(r domain.ExpectedDNSRecord, found bool) port.RecordVerification {
	return port.RecordVerification{Record: r, Found: found}
}

// mismatched models the other not-found shape the real verifier produces:
// the zone HAS a record at that name and type, but its value disagrees.
// verifyTLSA and friends set Actual to the live value and leave Found
// false (internal/adapter/dns/lookup.go).
//
// This shape is why the filter's predicate must be Found alone. Widening
// it to "we saw something at that name" would attest the value the RA
// expected while the zone serves a different one, which is a strictly
// worse false claim than the one this filter exists to remove.
func mismatched(r domain.ExpectedDNSRecord, live string) port.RecordVerification {
	return port.RecordVerification{Record: r, Found: false, Actual: live}
}

// lookupFailed models a per-record lookup fault. LookupVerifier only
// returns a hard error when it cannot resolve a nameserver at all; a
// SERVFAIL, REFUSED, or timeout on one record comes back as Found=false
// with Error set and Actual empty, and VerifyRecords still reports success.
func lookupFailed(r domain.ExpectedDNSRecord, errText string) port.RecordVerification {
	return port.RecordVerification{Record: r, Found: false, Error: errText}
}

func TestAttestedDNSRecords(t *testing.T) {
	t.Parallel()

	const (
		fqdn      = "agent.example.com"
		txtName   = "_ans.agent.example.com"
		badgeName = "_ans-badge.agent.example.com"
		tlsaName  = "_443._tcp.agent.example.com"
	)

	var (
		svcb  = rec(fqdn, domain.DNSRecordSVCB, "1 . alpn=mcp port=443", true)
		txt   = rec(txtName, domain.DNSRecordTXT, "v=ans1; ...", true)
		badge = rec(badgeName, domain.DNSRecordTXT, "v=ans-badge1; ...", true)
		tlsa  = rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 aabb", false)
		https = rec(fqdn, domain.DNSRecordHTTPS, "1 . alpn=h2", false)
	)

	cases := []struct {
		name      string
		expected  []domain.ExpectedDNSRecord
		perRecord []port.RecordVerification
		want      []domain.ExpectedDNSRecord
		// wantDropped pins the log-safe account of what was removed and
		// why. Asserting the cause matters as much as asserting the set:
		// the three not-found shapes are indistinguishable in the logs
		// without it, and only one of them is a normal operator choice.
		wantDropped []droppedRecord
	}{
		{
			// No verifier wired (local dev): verifyDNSRecords returns a nil
			// perRecord and treats DNS as correct. There is no observation to
			// filter against, so the expected set passes through and the
			// quickstart keeps emitting the full record list.
			name:        "nil_perRecord_passes_expected_through",
			expected:    []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			perRecord:   nil,
			want:        []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			wantDropped: nil,
		},
		{
			// The default-profile bug this filter exists to fix. Operator
			// published SVCB and badge, skipped the optional TLSA. Activation
			// succeeds either way; the leaf must not claim the TLSA.
			//
			// On real DNS this is the NXDOMAIN shape: declining DANE means
			// never creating `_443._tcp.<fqdn>`, so the name does not exist.
			// The adapter reports that as Found=false with Error empty, which
			// is why this drops as MISSING rather than LOOKUP_ERROR and stays
			// on the INFO arm.
			name:     "unpublished_optional_is_dropped",
			expected: []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			perRecord: []port.RecordVerification{
				verified(svcb, true), verified(badge, true), verified(tlsa, false),
			},
			want:        []domain.ExpectedDNSRecord{svcb, badge},
			wantDropped: []droppedRecord{{Name: tlsaName, Type: "TLSA", Cause: "MISSING"}},
		},
		{
			// The operator who did opt into DANE keeps their TLSA attested —
			// the filter narrows to observation, it does not blanket-drop
			// optional records.
			name:     "published_optional_is_kept",
			expected: []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			perRecord: []port.RecordVerification{
				verified(svcb, true), verified(badge, true), verified(tlsa, true),
			},
			want:        []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			wantDropped: nil,
		},
		{
			// The MISMATCH shape, and the reason the predicate is Found
			// alone. The operator's zone HAS a TLSA at that name, but it
			// binds a stale fingerprint from before a cert reissue. On an
			// unsigned zone this raises no 422 (TLSA is optional and the
			// DNSSEC hard-fail arm needs the AD bit), so it reaches the
			// seal. Attesting it would sign the fingerprint the RA
			// expected while the zone serves a different one.
			name:     "optional_with_mismatched_value_is_dropped",
			expected: []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			perRecord: []port.RecordVerification{
				verified(svcb, true), verified(badge, true), mismatched(tlsa, "3 0 1 ccdd"),
			},
			want:        []domain.ExpectedDNSRecord{svcb, badge},
			wantDropped: []droppedRecord{{Name: tlsaName, Type: "TLSA", Cause: "MISMATCH"}},
		},
		{
			// A resolver fault, and the precedence rule in dropCause. A
			// failed lookup leaves Actual empty, so classifying on Actual
			// first would report this as MISSING and hide an upstream
			// fault behind "the operator didn't publish it". The Error arm
			// runs first precisely to keep them apart.
			name:     "optional_lookup_error_is_dropped_and_not_reported_as_missing",
			expected: []domain.ExpectedDNSRecord{svcb, badge, tlsa},
			perRecord: []port.RecordVerification{
				verified(svcb, true), verified(badge, true), lookupFailed(tlsa, "rcode SERVFAIL"),
			},
			want: []domain.ExpectedDNSRecord{svcb, badge},
			wantDropped: []droppedRecord{
				{Name: tlsaName, Type: "TLSA", Cause: "LOOKUP_ERROR", Error: "rcode SERVFAIL"},
			},
		},
		{
			// Union mode (ANS_TXT + ANS_DNSAID): SVCB rows are flipped
			// Required=false and the apex HTTPS RR is optional. A CNAME-at-apex
			// operator structurally cannot publish HTTPS (RFC 1034 §3.6.2), so
			// the leaf must not assert it — while the TXT rows they did publish
			// survive.
			name:     "union_mode_drops_unpublishable_apex_https",
			expected: []domain.ExpectedDNSRecord{txt, https, badge},
			perRecord: []port.RecordVerification{
				verified(txt, true), verified(https, false), verified(badge, true),
			},
			want:        []domain.ExpectedDNSRecord{txt, badge},
			wantDropped: []droppedRecord{{Name: fqdn, Type: "HTTPS", Cause: "MISSING"}},
		},
		{
			// Ordering is load-bearing: ComputeRequiredDNSRecords regroups to
			// [discovery..., badge, TLSA] to pin the V2 canonical bytes, and
			// those bytes are what the RA signs and the TL dedupes on. The
			// filter walks `expected`, so relative order survives even though
			// perRecord arrives shuffled.
			name:     "preserves_expected_order_regardless_of_perRecord_order",
			expected: []domain.ExpectedDNSRecord{txt, svcb, badge, tlsa},
			perRecord: []port.RecordVerification{
				verified(tlsa, true), verified(badge, true),
				verified(svcb, true), verified(txt, true),
			},
			want:        []domain.ExpectedDNSRecord{txt, svcb, badge, tlsa},
			wantDropped: nil,
		},
		{
			// Why recordKey includes Value. Two TLSA rows share one owner name
			// and type during a cert rollover. The operator published the new
			// one and has not yet added the old one; keying on name+type alone
			// would let the found row vouch for the absent one.
			name:     "two_tlsa_at_one_name_attest_independently",
			expected: []domain.ExpectedDNSRecord{badge, tlsa, rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 ccdd", false)},
			perRecord: []port.RecordVerification{
				verified(badge, true),
				verified(tlsa, false),
				verified(rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 ccdd", false), true),
			},
			want:        []domain.ExpectedDNSRecord{badge, rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 ccdd", false)},
			wantDropped: []droppedRecord{{Name: tlsaName, Type: "TLSA", Cause: "MISSING"}},
		},
		{
			// A record absent from perRecord entirely (not merely Found=false)
			// is also unattestable — no evidence is not evidence. Guards
			// against a future verifier that returns a short result list.
			name:        "record_missing_from_perRecord_is_dropped",
			expected:    []domain.ExpectedDNSRecord{svcb, badge},
			perRecord:   []port.RecordVerification{verified(svcb, true)},
			want:        []domain.ExpectedDNSRecord{svcb},
			wantDropped: []droppedRecord{{Name: badgeName, Type: "TXT", Cause: "NO_RESULT"}},
		},
		{
			// Empty-but-non-nil perRecord is distinct from nil: the verifier
			// ran and answered with nothing, so nothing is attestable. Only a
			// nil perRecord means "no verifier wired".
			name:      "empty_perRecord_drops_everything",
			expected:  []domain.ExpectedDNSRecord{svcb, badge},
			perRecord: []port.RecordVerification{},
			want:      []domain.ExpectedDNSRecord{},
			wantDropped: []droppedRecord{
				{Name: fqdn, Type: "SVCB", Cause: "NO_RESULT"},
				{Name: badgeName, Type: "TXT", Cause: "NO_RESULT"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, dropped := attestedDNSRecords(tc.expected, tc.perRecord)
			if len(got) != len(tc.want) {
				t.Fatalf("attested count: got %d want %d (got %+v)", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("record[%d]: got %+v want %+v", i, got[i], tc.want[i])
				}
			}
			if len(dropped) != len(tc.wantDropped) {
				t.Fatalf("dropped count: got %d want %d (got %+v)", len(dropped), len(tc.wantDropped), dropped)
			}
			for i := range tc.wantDropped {
				if dropped[i] != tc.wantDropped[i] {
					t.Errorf("dropped[%d]: got %+v want %+v", i, dropped[i], tc.wantDropped[i])
				}
			}
			// Attested and dropped must together account for every
			// expected record exactly once. A record that fell out of both
			// would be silently missing from the leaf with nothing in the
			// logs to explain it.
			if tc.perRecord != nil && len(got)+len(dropped) != len(tc.expected) {
				t.Errorf("attested %d + dropped %d != expected %d", len(got), len(dropped), len(tc.expected))
			}
		})
	}
}

// TestAttestedDNSRecords_DropsNothingWhenAllFound pins the no-op case that
// keeps the quickstart and every noop-verifier test stable: the noop
// adapter reports Found=true for every record it is handed, so the filter
// must return the expected set unchanged rather than reordering or
// reallocating it into a different shape.
func TestAttestedDNSRecords_DropsNothingWhenAllFound(t *testing.T) {
	t.Parallel()
	expected := []domain.ExpectedDNSRecord{
		rec("_ans.a.example.com", domain.DNSRecordTXT, "v=ans1", true),
		rec("a.example.com", domain.DNSRecordSVCB, "1 . alpn=mcp", true),
		rec("_443._tcp.a.example.com", domain.DNSRecordTLSA, "3 0 1 ab", false),
	}
	perRecord := make([]port.RecordVerification, 0, len(expected))
	for _, r := range expected {
		perRecord = append(perRecord, verified(r, true))
	}
	got, dropped := attestedDNSRecords(expected, perRecord)
	if len(got) != len(expected) {
		t.Fatalf("count: got %d want %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("record[%d]: got %+v want %+v", i, got[i], expected[i])
		}
	}
	// No drops means the caller logs nothing at all, so a phantom entry
	// here would produce a log line contradicting the leaf.
	if len(dropped) != 0 {
		t.Errorf("want no dropped records, got %+v", dropped)
	}
}

// TestAttestedDNSRecords_DropSummaryIsLogSafe pins the log-safety
// contract on the summary the seal path emits. Record values hold cert
// fingerprints (TLSA) and endpoint metadata (SVCB, HTTPS, TXT), and the
// live value a mismatch turned up is operator zone content. None of it
// may reach log aggregation.
func TestAttestedDNSRecords_DropSummaryIsLogSafe(t *testing.T) {
	t.Parallel()
	const (
		expectedTLSA = "3 0 1 deadbeef"
		liveTLSA     = "3 0 1 cafebabe"
		expectedSVCB = "1 . alpn=mcp port=8443"
	)
	txtRec := rec("_ans.a.example.com", domain.DNSRecordTXT, "v=ans1", true)
	tlsaRec := rec("_443._tcp.a.example.com", domain.DNSRecordTLSA, expectedTLSA, false)
	svcbRec := rec("a.example.com", domain.DNSRecordSVCB, expectedSVCB, false)

	_, dropped := attestedDNSRecords(
		[]domain.ExpectedDNSRecord{txtRec, tlsaRec, svcbRec},
		[]port.RecordVerification{
			verified(txtRec, true),
			mismatched(tlsaRec, liveTLSA),
			lookupFailed(svcbRec, "rcode SERVFAIL"),
		},
	)
	if len(dropped) != 2 {
		t.Fatalf("dropped count: got %d want 2 (%+v)", len(dropped), dropped)
	}

	// Every field of every entry, checked against every value in play. The
	// struct has no Value field today, so this cannot fail now; it exists so
	// that adding one, or widening Error to carry a record body, fails here
	// instead of silently shipping cert fingerprints to a log aggregator.
	secrets := []string{expectedTLSA, liveTLSA, expectedSVCB, "v=ans1"}
	for _, d := range dropped {
		for _, field := range []string{d.Name, d.Type, d.Cause, d.Error} {
			for _, s := range secrets {
				if strings.Contains(field, s) {
					t.Errorf("record value %q leaked into the log summary: %+v", s, d)
				}
			}
		}
	}

	// The resolver's own message is the one thing that must survive: it is
	// why the record went unattested, and nothing else in the RA reports it.
	if dropped[1].Cause != dropCauseLookupError || dropped[1].Error != "rcode SERVFAIL" {
		t.Errorf("resolver failure must reach the log with its cause: %+v", dropped[1])
	}
}

// TestDropCauseMatchesLookupAdapterShapes is the seam test between this
// classification and the adapter that feeds it. Every case below is the
// exact port.RecordVerification the real LookupVerifier emits for one DNS
// outcome, so the two stay in agreement.
//
// This exists because the classification is only as good as the adapter's
// contract, and that contract is easy to get wrong in a way no
// service-level test would catch: the adapter used to report NXDOMAIN
// through Error, which put the single most common drop — an operator
// declining DANE, which yields NXDOMAIN on real DNS because the
// `_443._tcp` owner name is never created — on the LOOKUP_ERROR/WARN arm.
// Hand-built fixtures modelled absence as Error=="" and so agreed with the
// intent while the adapter disagreed with both. The adapter side is pinned
// by TestLookupVerifier_AbsenceShapesAndFaultsAreDistinguishable; this is
// the other half.
func TestDropCauseMatchesLookupAdapterShapes(t *testing.T) {
	t.Parallel()
	rec := rec("_443._tcp.a.example.com", domain.DNSRecordTLSA, "3 0 1 abcd", false)

	cases := []struct {
		name string
		// dnsOutcome names the real-world DNS response this models.
		dnsOutcome string
		v          port.RecordVerification
		haveResult bool
		want       string
	}{
		{
			name:       "nxdomain",
			dnsOutcome: "NXDOMAIN — owner name absent; the skip-DANE case",
			v:          port.RecordVerification{Record: rec},
			haveResult: true,
			want:       dropCauseMissing,
		},
		{
			name:       "nodata",
			dnsOutcome: "NOERROR, empty answer — name exists, no record of this type",
			v:          port.RecordVerification{Record: rec},
			haveResult: true,
			want:       dropCauseMissing,
		},
		{
			name:       "value_disagrees",
			dnsOutcome: "NOERROR with a record whose value differs (stale fingerprint)",
			v:          port.RecordVerification{Record: rec, Actual: "3 0 1 ffff"},
			haveResult: true,
			want:       dropCauseMismatch,
		},
		{
			name:       "servfail",
			dnsOutcome: "SERVFAIL — the question went unanswered",
			v:          port.RecordVerification{Record: rec, Error: "rcode SERVFAIL"},
			haveResult: true,
			want:       dropCauseLookupError,
		},
		{
			name:       "refused",
			dnsOutcome: "REFUSED — likewise a fault, not an answer",
			v:          port.RecordVerification{Record: rec, Error: "rcode REFUSED"},
			haveResult: true,
			want:       dropCauseLookupError,
		},
		{
			name:       "transport_failure",
			dnsOutcome: "no response at all (timeout / unreachable resolver)",
			v:          port.RecordVerification{Record: rec, Error: "read udp: i/o timeout"},
			haveResult: true,
			want:       dropCauseLookupError,
		},
		{
			name:       "no_result_for_record",
			dnsOutcome: "verifier returned a short result list — no evidence either way",
			v:          port.RecordVerification{},
			haveResult: false,
			want:       dropCauseNoResult,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dropCause(tc.v, tc.haveResult); got != tc.want {
				t.Errorf("%s\n  got %q want %q", tc.dnsOutcome, got, tc.want)
			}
		})
	}
}

// TestDroppedForLookupError pins the level gate. The distinction is the
// point of the whole summary: an operator skipping an optional record is
// INFO, an upstream resolver fault that narrowed a signed leaf is WARN.
func TestDroppedForLookupError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		dropped []droppedRecord
		want    bool
	}{
		{"nothing_dropped", nil, false},
		{"operator_skipped", []droppedRecord{{Cause: dropCauseMissing}}, false},
		{"stale_value", []droppedRecord{{Cause: dropCauseMismatch}}, false},
		{"no_result", []droppedRecord{{Cause: dropCauseNoResult}}, false},
		{"resolver_failed", []droppedRecord{{Cause: dropCauseLookupError}}, true},
		{
			// One fault among ordinary drops still has to escalate, or a
			// SERVFAIL hides behind an operator's skipped TLSA.
			"one_fault_among_normal_drops",
			[]droppedRecord{{Cause: dropCauseMissing}, {Cause: dropCauseLookupError}},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := droppedForLookupError(tc.dropped); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}
