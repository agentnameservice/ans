package port

import (
	"context"

	"github.com/godaddy/ans/internal/domain"
)

// RecordVerification is the result of checking a single DNS record.
type RecordVerification struct {
	Record domain.ExpectedDNSRecord
	Found  bool
	// Actual carries the live answer DNS returned for this record. When
	// records exist for the name/type but none matched the expected
	// value, Actual is the first live answer (so the verify-dns 422 can
	// show the operator what is actually in their zone). When nothing
	// answered at all, Actual is empty. The service layer partitions on
	// exactly this: !Found && Actual == "" is MISSING, !Found && Actual
	// != "" is a value MISMATCH. When Found is true, Actual MAY differ
	// benignly from the expected value (e.g. an SVCB subset match where
	// the live record carries coexistence extras) and is informational
	// only — Found is the verdict.
	Actual string
	Error  string // Lookup error, if any.
	// DNSSECVerified is true when the response carried an
	// authenticated-data (AD) bit from a validating resolver. Set
	// on TLSA, SVCB, and HTTPS responses; surfaced to the TL
	// attestation so a downstream verifier can trust the cert /
	// capability / service binding without re-querying DNS. The
	// service layer enforces a hard-fail rule when AD=true and the
	// record's value disagrees with the expected one (the threat
	// shape: an attacker rewrote a record in a DNSSEC-signed zone).
	DNSSECVerified bool
}

// VerificationResult aggregates per-record results from a DNS verification run.
type VerificationResult struct {
	// AllRequired is true when every record marked Required was found
	// with a matching value.
	AllRequired bool
	Results     []RecordVerification
}

// DNSVerifier checks that the operator's DNS zone contains the records
// the domain expects. It does NOT create, update, or delete records —
// ANS is verification-only. Operators manage their own DNS.
type DNSVerifier interface {
	// VerifyRecords performs DNS lookups for each expected record and
	// returns a per-record report plus an overall pass/fail summary.
	// A VerificationResult is always returned even on partial failures;
	// a non-nil error indicates a systemic failure (e.g., DNS unreachable).
	VerifyRecords(
		ctx context.Context,
		fqdn string,
		expected []domain.ExpectedDNSRecord,
	) (*VerificationResult, error)
}
