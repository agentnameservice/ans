package service

import (
	"github.com/rs/zerolog/log"

	"github.com/agentnameservice/ans/internal/domain"
)

// ComputeRequiredDNSRecords returns the DNS records the operator must
// publish for reg, composed by walking the discovery registry. The RA
// does not create these records — the operator manages their own DNS;
// the RA only verifies they exist and emits the same set onto the TL
// as `dnsRecordsProvisioned[]`.
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
			key := r.Name + "|" + string(r.Type) + "|" + r.Value
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
