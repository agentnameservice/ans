package port

import (
	"context"

	"github.com/godaddy/ans/internal/domain"
)

// RecordVerification is the result of checking a single DNS record.
type RecordVerification struct {
	Record domain.ExpectedDNSRecord
	Found  bool
	Actual string // What was actually returned by DNS (empty if not found).
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
