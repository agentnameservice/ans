package service

import (
	"github.com/rs/zerolog/log"

	"github.com/godaddy/ans/internal/domain"
)

// ComputeRequiredDNSRecords returns the DNS records the operator must
// publish for reg, composed by walking the discovery registry. The RA
// does not create these records — the operator manages their own DNS;
// the RA only verifies they exist and emits the same set onto the TL
// as `dnsRecordsProvisioned[]`.
//
// Composition rules:
//
//  1. The set of styles to emit is reg.DNSRecordStyles, filtered to
//     those the registry actually has wired. Empty after filtering
//     (operator omitted dnsRecordStyles, or every entry was unknown
//     to the registry) normalizes to domain.DefaultDNSRecordStyles().
//  2. Iteration order is the registry's insertion order (cmd/main
//     wires [TXTStyle, SVCBStyle], so emission proceeds TXT-first
//     then SVCB). User-supplied order on reg.DNSRecordStyles has no
//     effect — `dnsRecordStyles` is set semantics on the wire.
//  3. Each style's full record list (discovery + family trust records)
//     is collected and deduped by (Name, Type, Value). Family trust
//     records that overlap across sibling styles in the same family
//     (e.g. `_ans-badge` from both ANS_SVCB and ANS_TXT) emit once.
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
// Returns nil when reg has no endpoints AND no server cert (nothing
// meaningful for the operator to publish), matching the pre-refactor
// domain function's empty-input contract.
//
// s.discoveryRegistry is guaranteed non-nil by NewRegistrationService
// (constructor panics on nil), so the walker dereferences it
// unconditionally.
func (s *RegistrationService) ComputeRequiredDNSRecords(reg *domain.AgentRegistration) []domain.ExpectedDNSRecord {
	requested := s.resolveRequestedStyles(reg)

	logger := log.Debug().
		Str("agentId", reg.AgentID).
		Strs("requestedStyles", styleStrings(reg.DNSRecordStyles)).
		Strs("resolvedStyles", styleStrings(setToSlice(requested)))
	logger.Msg("computing required DNS records")

	collected, seen := []domain.ExpectedDNSRecord{}, make(map[string]bool)
	for _, id := range s.discoveryRegistry.IDs() {
		if !requested[id] {
			continue
		}
		style, ok := s.discoveryRegistry.Get(id)
		if !ok {
			continue
		}
		emitted := style.Records(reg)
		log.Debug().
			Str("agentId", reg.AgentID).
			Str("style", string(id)).
			Int("emittedCount", len(emitted)).
			Msg("style emitted records")
		for _, r := range emitted {
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
	if requested[domain.DNSRecordStyleTXT] {
		for i := range result {
			if result[i].Type == domain.DNSRecordSVCB {
				result[i].Required = false
			}
		}
	}

	if len(result) == 0 && len(reg.Endpoints) > 0 {
		log.Warn().
			Str("agentId", reg.AgentID).
			Strs("resolvedStyles", styleStrings(setToSlice(requested))).
			Msg("DNS record computation produced no records despite having endpoints; check discovery registry wiring")
	}

	return result
}

// resolveRequestedStyles filters reg.DNSRecordStyles to those the
// registry has wired, normalizing empty/all-invalid to the default
// set. Unknown styles trigger a WARN log so an operator can spot a
// post-decommission row in their data without parsing verify-dns
// failures.
func (s *RegistrationService) resolveRequestedStyles(reg *domain.AgentRegistration) map[domain.DNSRecordStyle]bool {
	requested := make(map[domain.DNSRecordStyle]bool)
	for _, id := range reg.DNSRecordStyles {
		if _, ok := s.discoveryRegistry.Get(id); ok {
			requested[id] = true
			continue
		}
		log.Warn().
			Str("agentId", reg.AgentID).
			Str("style", string(id)).
			Msg("registration carries DNS style unknown to the running registry; skipping")
	}
	if len(requested) == 0 {
		for _, id := range domain.DefaultDNSRecordStyles() {
			requested[id] = true
		}
	}
	return requested
}

func styleStrings(styles []domain.DNSRecordStyle) []string {
	out := make([]string, len(styles))
	for i, s := range styles {
		out[i] = string(s)
	}
	return out
}

// setToSlice converts the requested-set map to a deterministic slice
// for logging. Order tracks domain.ValidDNSRecordStyles() so logs are
// stable across runs.
func setToSlice(set map[domain.DNSRecordStyle]bool) []domain.DNSRecordStyle {
	var out []domain.DNSRecordStyle
	for _, valid := range domain.ValidDNSRecordStyles() {
		id := domain.DNSRecordStyle(valid)
		if set[id] {
			out = append(out, id)
		}
	}
	return out
}
