package service

import (
	"github.com/rs/zerolog/log"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// ComputeRequiredDNSRecords returns the DNS records the operator must
// publish for reg, composed by walking the discovery registry. The RA
// does not create these records — the operator manages their own DNS;
// the RA only verifies they exist.
//
// This is the asked-for set, not the attested set. What reaches the TL
// as `dnsRecordsProvisioned[]` is this set narrowed to the records DNS
// actually answered with; see attestedDNSRecords.
//
// Composition rules:
//
//  1. The set of profiles to emit is reg.DiscoveryProfiles, filtered to
//     those the registry actually has wired. Empty after filtering
//     (operator omitted discoveryProfiles, or every entry was unknown
//     to the registry) normalizes to domain.DefaultDiscoveryProfiles().
//  2. Iteration order is the registry's insertion order (cmd/main
//     wires [TXTProfile, DNSAIDProfile], so emission proceeds TXT-first
//     then SVCB). User-supplied order on reg.DiscoveryProfiles has no
//     effect — `discoveryProfiles` is set semantics on the wire.
//  3. Each profile's full record list (discovery + family trust records)
//     is collected and deduped by (Name, Type, Value). Family trust
//     records that overlap across sibling profiles in the same family
//     (e.g. `_ans-badge` from both ANS_DNSAID and ANS_TXT) emit once.
//  4. Records are reordered into discovery-then-trust groupings,
//     preserving within-group iteration order. This pins the V2 TL
//     `dnsRecordsProvisioned[]` canonical bytes for the union case
//     to the historical `[discovery..., badge, TLSA]` shape.
//  5. SVCB rows arrive from the adapter with Required=true. When TXT
//     is also resolved, every SVCB row is post-processed to
//     Required=false — during the §4.4.2 transition the legacy
//     `_ans` TXT family carries the operator's required signal and
//     SVCB rides along as optional.
//
// Returns an empty (non-nil) slice when reg has no endpoints AND no
// server cert — nothing meaningful for the operator to publish. The
// nil-vs-empty distinction never reaches the wire: the V2 event
// builder re-wraps into its own slice.
//
// s.discoveryRegistry is guaranteed non-nil by NewRegistrationService
// (constructor panics on nil), so the walker dereferences it
// unconditionally.
func (s *RegistrationService) ComputeRequiredDNSRecords(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	requested := s.resolveRequestedProfiles(reg)

	logger := log.Debug().
		Str("agentId", reg.AgentID).
		Strs("requestedProfiles", profileStrings(reg.DiscoveryProfiles)).
		Strs("resolvedProfiles", profileStrings(setToSlice(requested)))
	logger.Msg("computing required DNS records")

	collected, seen := []domain.ExpectedDNSRecord{}, make(map[string]bool)
	for _, id := range s.discoveryRegistry.IDs() {
		if !requested[id] {
			continue
		}
		profile, ok := s.discoveryRegistry.Get(id)
		if !ok {
			continue
		}
		emitted := profile.Records(reg)
		log.Debug().
			Str("agentId", reg.AgentID).
			Str("profile", string(id)).
			Int("emittedCount", len(emitted)).
			Msg("profile emitted records")
		for _, r := range emitted {
			// Dedup key deliberately omits Required: sibling profiles
			// emitting the same family trust record (badge, TLSA) must
			// agree on the flag (both adapters do — badge true, TLSA
			// false), so first-seen wins. A profile that disagreed
			// would have its flag silently dropped here — keep the
			// flags aligned across adapters.
			key := recordKey(r)
			if seen[key] {
				continue
			}
			seen[key] = true
			collected = append(collected, r)
		}
	}

	// Group: discovery records first (in walker order), then trust
	// records (badge, TLSA) — preserves the V2 union-case canonical
	// bytes shape `[discovery..., badge, TLSA]`.
	result := make([]domain.ExpectedDNSRecord, 0, len(collected))
	var trust []domain.ExpectedDNSRecord
	for _, r := range collected {
		if r.Purpose == domain.PurposeDiscovery {
			result = append(result, r)
		} else {
			trust = append(trust, r)
		}
	}
	result = append(result, trust...)

	// SVCB Required-flag post-process: §4.4.2 says TXT carries the
	// required signal during the transition; SVCB stays optional
	// alongside.
	if requested[domain.DiscoveryProfileANSTXT] {
		for i := range result {
			if result[i].Type == domain.DNSRecordSVCB {
				result[i].Required = false
			}
		}
	}

	if len(result) == 0 && len(reg.Endpoints) > 0 {
		log.Warn().
			Str("agentId", reg.AgentID).
			Strs("resolvedProfiles", profileStrings(setToSlice(requested))).
			Msg("DNS record computation produced no records despite having endpoints; check discovery registry wiring")
	}

	return result
}

// recordKey identifies one expected record by the three fields that
// make it distinct on the wire: owner name, RR type, and presentation
// value. Value is part of the key because a single owner name legitimately
// carries several records of the same type — two TLSA rows at
// `_443._tcp.<fqdn>` during a cert rollover, for instance — and collapsing
// them would make the dedup in ComputeRequiredDNSRecords drop one and the
// filter in attestedDNSRecords attest one on the other's evidence.
//
// Required is deliberately excluded; see the dedup call site above.
func recordKey(r domain.ExpectedDNSRecord) string {
	return r.Name + "|" + string(r.Type) + "|" + r.Value
}

// attestedDNSRecords narrows the expected record set to the records DNS
// actually answered with, so the AGENT_REGISTERED leaf's
// `dnsRecordsProvisioned[]` states what was observed rather than what was
// asked for.
//
// This matters because optional records do not block activation. An
// operator who publishes the required discovery and badge records but no
// TLSA passes verify-dns — verifyDNSRecords skips absent optional records
// by design, and DNSSEC does not help since authenticated absence is not
// tampering. Iterating `expected` at that point would sign "TLSA is
// provisioned" into an append-only log for an operator who never published
// one. The apex HTTPS RR is worse: CNAME-at-apex operators cannot publish
// it at all (RFC 1034 §3.6.2), so the claim could never come true.
//
// The predicate is `Found` alone. Required records need no separate arm:
// a required record that was missing or mismatched comes back from
// verifyDNSRecords as a mismatch, and VerifyDNS returns 422 before the
// seal, so by the time this runs every required record is Found.
//
// A nil perRecord means the service was built without a DNS verifier (the
// test/embedding path — cmd/ans-ra always wires one, `noop` included), so
// verifyDNSRecords short-circuits to "DNS is correct". There is no
// observation to filter on, so expected passes through unchanged, matching
// that path's existing contract. An empty-but-non-nil perRecord is
// different: the verifier ran and reported nothing, so nothing is
// attestable.
//
// Iteration walks `expected` rather than perRecord so the deliberate
// `[discovery..., badge, TLSA]` grouping that pins the V2 canonical bytes
// survives the filter. Keys match exactly, with no case or trailing-dot
// normalization, because the verifier echoes back the same
// ExpectedDNSRecord struct it was handed.
//
// The second return is the log-safe account of what was removed and why.
// It comes from this same pass deliberately: a separate helper
// recomputing "what got dropped" could disagree with the filter, and the
// disagreement would surface as a log line that misdescribes a signed
// leaf.
func attestedDNSRecords(
	expected []domain.ExpectedDNSRecord, perRecord []port.RecordVerification,
) ([]domain.ExpectedDNSRecord, []droppedRecord) {
	if perRecord == nil {
		return expected, nil
	}
	// One entry per key: ComputeRequiredDNSRecords dedups `expected` on
	// exactly recordKey, and the port contract is one result per expected
	// record, so the map is 1:1 with no collisions to resolve.
	byKey := make(map[string]port.RecordVerification, len(perRecord))
	for _, r := range perRecord {
		byKey[recordKey(r.Record)] = r
	}
	attested := make([]domain.ExpectedDNSRecord, 0, len(expected))
	var dropped []droppedRecord
	for _, r := range expected {
		v, ok := byKey[recordKey(r)]
		if ok && v.Found {
			attested = append(attested, r)
			continue
		}
		dropped = append(dropped, droppedRecord{
			Name:  r.Name,
			Type:  string(r.Type),
			Cause: dropCause(v, ok),
			Error: v.Error,
		})
	}
	return attested, dropped
}

// Causes reported on a dropped record. MISSING and MISMATCH reuse the 422
// classification codes so one vocabulary covers both surfaces.
// LOOKUP_ERROR and NO_RESULT have no 422 equivalent: a required record
// failing either way is reported as MISSING and blocks activation, so they
// only ever reach the seal on an optional record.
const (
	dropCauseMissing     = dnsCodeMissing
	dropCauseMismatch    = dnsCodeMismatch
	dropCauseLookupError = "LOOKUP_ERROR"
	dropCauseNoResult    = "NO_RESULT"
)

// droppedRecord is the log-safe view of a record attestedDNSRecords
// removed. Name, type and cause only: record values carry cert
// fingerprints and endpoint metadata that have no business in log
// aggregation, matching the 422 mismatch log's discipline. Error is the
// resolver's own text (an rcode or a network error), present only on the
// LOOKUP_ERROR cause.
type droppedRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Cause string `json:"cause"`
	Error string `json:"error,omitempty"`
}

// dropCause classifies why a record went unattested. Without this the
// three causes are indistinguishable in the logs, and they are not
// equivalent: an operator skipping DANE is a normal choice, a value that
// disagrees means their zone contradicts the cert just issued, and a
// failed lookup means an upstream fault silently narrowed a signed leaf.
//
// The Error arm comes first on purpose. A failed lookup leaves Actual
// empty, so it would otherwise be reported as MISSING — exactly the
// conflation that hides a SERVFAILing resolver behind "operator didn't
// publish it". Nothing else in the RA reads
// port.RecordVerification.Error, so this is the only place that fault
// becomes visible.
func dropCause(v port.RecordVerification, haveResult bool) string {
	switch {
	case !haveResult:
		return dropCauseNoResult
	case v.Error != "":
		return dropCauseLookupError
	case v.Actual == "":
		return dropCauseMissing
	default:
		return dropCauseMismatch
	}
}

// droppedForLookupError reports whether any record went unattested because
// the lookup itself failed rather than because of the zone's contents.
// Callers log those at WARN: LookupVerifier only returns a hard error when
// it cannot find a resolver at all, so a per-record SERVFAIL, REFUSED, or
// timeout arrives looking like a clean not-found.
func droppedForLookupError(dropped []droppedRecord) bool {
	for _, d := range dropped {
		if d.Cause == dropCauseLookupError {
			return true
		}
	}
	return false
}

// resolveRequestedProfiles filters reg.DiscoveryProfiles to those the
// registry has wired, normalizing empty/all-invalid to the default
// set. Unknown profiles trigger a WARN log so an operator can spot a
// post-decommission row in their data without parsing verify-dns
// failures.
func (s *RegistrationService) resolveRequestedProfiles(reg *domain.AgentRegistration) map[domain.DiscoveryProfile]bool {
	requested := make(map[domain.DiscoveryProfile]bool)
	for _, id := range reg.DiscoveryProfiles {
		if _, ok := s.discoveryRegistry.Get(id); ok {
			requested[id] = true
			continue
		}
		log.Warn().
			Str("agentId", reg.AgentID).
			Str("profile", string(id)).
			Msg("registration carries discovery profile unknown to the running registry; skipping")
	}
	if len(requested) == 0 {
		if len(reg.DiscoveryProfiles) > 0 {
			// Non-empty requested set collapsed to the default: every
			// requested profile was unknown to the running registry (e.g.
			// a stale value from before a rename, or a profile this
			// deployment doesn't wire). The agent will be verified against
			// the default record set, not what it published — surface this
			// distinctly so it isn't mistaken for an operator zone error at
			// verify-dns.
			log.Warn().
				Str("agentId", reg.AgentID).
				Strs("requestedProfiles", profileStrings(reg.DiscoveryProfiles)).
				Strs("defaultProfiles", profileStrings(domain.DefaultDiscoveryProfiles())).
				Msg("all requested discovery profiles were unknown to the running registry; falling back to the default set")
		}
		for _, id := range domain.DefaultDiscoveryProfiles() {
			requested[id] = true
		}
	}
	return requested
}

func profileStrings(profiles []domain.DiscoveryProfile) []string {
	out := make([]string, len(profiles))
	for i, s := range profiles {
		out[i] = string(s)
	}
	return out
}

// setToSlice converts the requested-set map to a deterministic slice
// for logging. Order tracks domain.ValidDiscoveryProfiles() so logs are
// stable across runs.
func setToSlice(set map[domain.DiscoveryProfile]bool) []domain.DiscoveryProfile {
	var out []domain.DiscoveryProfile
	for _, valid := range domain.ValidDiscoveryProfiles() {
		id := domain.DiscoveryProfile(valid)
		if set[id] {
			out = append(out, id)
		}
	}
	return out
}
