package service_test

// End-to-end cover for the attestation narrowing: drive a registration
// all the way to ACTIVE against a verifier that reports the optional
// TLSA row as unpublished, then read the sealed AGENT_REGISTERED leaf
// and check it does not claim that row.
//
// The unit tests for the filter itself live in
// dnsattest_internal_test.go. What these add is the wiring: that the
// filtered set is what reaches both event builders, and that dropping a
// record does not disturb activation.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/ra/service"
	event "github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
)

// selectiveDNSVerifier answers per record against the set it was handed:
// everything is found except records whose type appears in absent, which
// come back the way an unpublished record does — not found, with no live
// answer, which is the MISSING half of the port.RecordVerification
// contract rather than a mismatch.
//
// The two existing stubs return a fixed result list and ignore their
// input, so neither can model "the operator published the required
// records and skipped the optional one" against the record set
// ComputeRequiredDNSRecords actually built.
type selectiveDNSVerifier struct {
	// absent: the zone has no record of this type.
	absent map[domain.DNSRecordType]bool
	// lookupError: the query for this type failed. LookupVerifier reports
	// that as Found=false with Error set and still returns success
	// overall, so it is indistinguishable from an absent record unless
	// something reads Error.
	lookupError map[domain.DNSRecordType]string

	mu     sync.Mutex
	calls  int
	handed []domain.ExpectedDNSRecord
}

func (v *selectiveDNSVerifier) VerifyRecords(
	_ context.Context, _ string, expected []domain.ExpectedDNSRecord,
) (*port.VerificationResult, error) {
	v.mu.Lock()
	v.calls++
	v.handed = append(v.handed, expected...)
	v.mu.Unlock()

	res := &port.VerificationResult{
		AllRequired: true,
		Results:     make([]port.RecordVerification, 0, len(expected)),
	}
	for _, r := range expected {
		errText := v.lookupError[r.Type]
		found := errText == "" && !v.absent[r.Type]
		if !found && r.Required {
			res.AllRequired = false
		}
		// Actual stays empty on both not-found paths: nothing answered, so
		// there is no live value that could have been rewritten. A failed
		// lookup carries Error instead.
		res.Results = append(res.Results, port.RecordVerification{
			Record: r, Found: found, Error: errText,
		})
	}
	return res, nil
}

func (v *selectiveDNSVerifier) observed() (int, []domain.ExpectedDNSRecord) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls, append([]domain.ExpectedDNSRecord(nil), v.handed...)
}

// activateWithAbsentTLSA registers an agent, clears the ACME gate on the
// fixture's noop verifier, then swaps in a verifier that reports the
// optional TLSA row unpublished before verify-dns. The swap happens
// after verify-acme on purpose: the gate does its own challenge lookup,
// and keeping that on the noop verifier means the records handed to the
// selective one are exactly the production record set.
//
// Returns the records verify-dns asked about, so callers can derive what
// the leaf should and should not carry rather than hardcoding names the
// discovery profiles own.
func activateWithAbsentTLSA(t *testing.T, schemaVersion string) (*regFixture, []domain.ExpectedDNSRecord) {
	t.Helper()
	return activateWithTLSAUnverified(t, schemaVersion,
		&selectiveDNSVerifier{absent: map[domain.DNSRecordType]bool{domain.DNSRecordTLSA: true}})
}

// activateWithTLSAUnverified is activateWithAbsentTLSA parameterized by the
// reason the TLSA row goes unverified, so the absent case and the
// lookup-failure case share one path to the seal.
func activateWithTLSAUnverified(
	t *testing.T, schemaVersion string, v *selectiveDNSVerifier,
) (*regFixture, []domain.ExpectedDNSRecord) {
	t.Helper()
	fx := newRegFixture(t)
	req := fx.req
	req.SchemaVersion = schemaVersion

	resp, err := fx.svc.RegisterAgent(context.Background(), req)
	if err != nil {
		t.Fatalf("precondition: register should succeed; got: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{SchemaVersion: schemaVersion}); err != nil {
		t.Fatalf("precondition: verify-acme should pass the gate; got: %v", err)
	}

	fx.svc.WithDNSVerifier(v)

	if _, err := fx.svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{SchemaVersion: schemaVersion}); err != nil {
		t.Fatalf("an unpublished optional record must not block activation; verify-dns failed: %v", err)
	}

	got, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindByAgentID: %v", err)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("agent must reach ACTIVE with the optional TLSA unpublished; got %q", got.Status)
	}

	calls, handed := v.observed()
	// One call keeps the counting assertions below honest — a second
	// round of lookups would duplicate every record in handed.
	if calls != 1 {
		t.Fatalf("verify-dns should verify the record set once; got %d calls", calls)
	}
	// Guard the premise. If the default profile set stops emitting an
	// optional TLSA row, this test silently stops covering anything, so
	// fail here rather than pass vacuously.
	sawOptionalTLSA := false
	sawRequired := false
	for _, r := range handed {
		if r.Type == domain.DNSRecordTLSA && !r.Required {
			sawOptionalTLSA = true
		}
		if r.Required {
			sawRequired = true
		}
	}
	if !sawOptionalTLSA {
		t.Fatalf("premise: expected an optional TLSA record in the computed set; got %+v", handed)
	}
	if !sawRequired {
		t.Fatalf("premise: expected at least one required record in the computed set; got %+v", handed)
	}
	return fx, handed
}

// partitionHanded splits the records verify-dns asked about into the ones
// the verifier reported found and the ones it reported absent.
func partitionHanded(handed []domain.ExpectedDNSRecord) (published, unpublished []domain.ExpectedDNSRecord) {
	for _, r := range handed {
		if r.Type == domain.DNSRecordTLSA {
			unpublished = append(unpublished, r)
			continue
		}
		published = append(published, r)
	}
	return published, unpublished
}

// TestVerifyDNS_SealedV2LeafOmitsUnpublishedOptionalRecord is the
// regression this whole change exists for. The V2 leaf's
// dnsRecordsProvisioned[] used to be built from the expected set, so an
// operator who skipped the optional TLSA got a signed, append-only claim
// that they had published one.
func TestVerifyDNS_SealedV2LeafOmitsUnpublishedOptionalRecord(t *testing.T) {
	t.Parallel()
	fx, handed := activateWithAbsentTLSA(t, "")
	published, unpublished := partitionHanded(handed)

	var attested []event.DNSRecord
	sawV2 := false
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion != event.SchemaVersion {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(s.InnerCanonical, &ev); err != nil {
			t.Fatalf("unmarshal inner V2 event: %v", err)
		}
		if ev.EventType != event.TypeAgentRegistered {
			continue
		}
		sawV2 = true
		if ev.Attestations == nil {
			t.Fatal("V2 AGENT_REGISTERED must carry attestations")
		}
		attested = ev.Attestations.DNSRecordsProvisioned
	}
	if !sawV2 {
		t.Fatal("expected a sealed V2 AGENT_REGISTERED event")
	}

	inLeaf := make(map[string]bool, len(attested))
	for _, r := range attested {
		inLeaf[r.Name+"|"+r.Type+"|"+r.Data] = true
	}
	for _, r := range unpublished {
		key := r.Name + "|" + string(r.Type) + "|" + r.Value
		if inLeaf[key] {
			t.Errorf("leaf attests %s %s, which DNS did not answer with", r.Type, r.Name)
		}
	}
	for _, r := range published {
		key := r.Name + "|" + string(r.Type) + "|" + r.Value
		if !inLeaf[key] {
			t.Errorf("leaf is missing %s %s, which DNS did answer with", r.Type, r.Name)
		}
	}
	// Count check catches the other direction: a record in the leaf that
	// verify-dns never asked about.
	if len(attested) != len(published) {
		t.Errorf("leaf record count: got %d want %d (attested %+v)", len(attested), len(published), attested)
	}
}

// TestVerifyDNS_SealedV1LeafOmitsUnpublishedOptionalRecord covers the
// other lane. V1's dnsRecordsProvisioned is a map[name]data, built by a
// separate builder, so the shared filter needs pinning on both sides.
func TestVerifyDNS_SealedV1LeafOmitsUnpublishedOptionalRecord(t *testing.T) {
	t.Parallel()
	fx, handed := activateWithAbsentTLSA(t, eventv1.SchemaVersion)
	published, unpublished := partitionHanded(handed)

	var attested map[string]string
	sawV1 := false
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion != eventv1.SchemaVersion {
			continue
		}
		var ev eventv1.Event
		if err := json.Unmarshal(s.InnerCanonical, &ev); err != nil {
			t.Fatalf("unmarshal inner V1 event: %v", err)
		}
		if ev.EventType != eventv1.TypeAgentRegistered {
			continue
		}
		sawV1 = true
		if ev.Attestations == nil {
			t.Fatal("V1 AGENT_REGISTERED must carry attestations")
		}
		attested = ev.Attestations.DNSRecordsProvisioned
	}
	if !sawV1 {
		t.Fatal("expected a sealed V1 AGENT_REGISTERED event")
	}

	// V1 keys on name alone, so a dropped record only proves anything if
	// no surviving record shares its owner name.
	publishedNames := make(map[string]bool, len(published))
	for _, r := range published {
		publishedNames[r.Name] = true
		if attested[r.Name] != r.Value {
			t.Errorf("V1 map for %s: got %q want %q", r.Name, attested[r.Name], r.Value)
		}
	}
	for _, r := range unpublished {
		if publishedNames[r.Name] {
			continue
		}
		if _, ok := attested[r.Name]; ok {
			t.Errorf("V1 map attests %s, which DNS did not answer with", r.Name)
		}
	}
	// The skip above exists because V1 keys on name alone, but if it fired
	// for every dropped record the negative assertion would be vacuous and
	// this test would pin nothing. Fail loudly rather than pass silently.
	provedSomething := false
	for _, r := range unpublished {
		if !publishedNames[r.Name] {
			provedSomething = true
		}
	}
	if len(unpublished) > 0 && !provedSomething {
		t.Fatal("vacuous: every dropped record shares an owner name with a surviving one, so nothing was asserted")
	}
}

// TestVerifyDNS_LookupFailureOnOptionalRecordStillActivatesAndNarrows covers
// the fault the absent-record tests cannot reach. LookupVerifier returns a
// hard error only when it cannot resolve a nameserver at all; a SERVFAIL,
// REFUSED, or timeout on one record comes back as a clean not-found with
// Error set, and VerifyRecords still reports overall success.
//
// TLSA, HTTPS, and SVCB are exactly the query types older resolvers and
// middleboxes drop while TXT keeps working, so a partial failure that
// leaves the required records healthy is the ordinary shape of this fault.
// The agent must still activate, and the leaf must not attest a record the
// RA never actually saw.
func TestVerifyDNS_LookupFailureOnOptionalRecordStillActivatesAndNarrows(t *testing.T) {
	t.Parallel()
	fx, handed := activateWithTLSAUnverified(t, "", &selectiveDNSVerifier{
		lookupError: map[domain.DNSRecordType]string{domain.DNSRecordTLSA: "rcode SERVFAIL"},
	})
	published, unverified := partitionHanded(handed)

	var attested []event.DNSRecord
	sawV2 := false
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion != event.SchemaVersion {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(s.InnerCanonical, &ev); err != nil {
			t.Fatalf("unmarshal inner V2 event: %v", err)
		}
		if ev.EventType != event.TypeAgentRegistered {
			continue
		}
		sawV2 = true
		if ev.Attestations == nil {
			t.Fatal("V2 AGENT_REGISTERED must carry attestations")
		}
		attested = ev.Attestations.DNSRecordsProvisioned
	}
	if !sawV2 {
		t.Fatal("expected a sealed V2 AGENT_REGISTERED event")
	}

	inLeaf := make(map[string]bool, len(attested))
	for _, r := range attested {
		inLeaf[r.Name+"|"+r.Type+"|"+r.Data] = true
	}
	for _, r := range unverified {
		if inLeaf[r.Name+"|"+string(r.Type)+"|"+r.Value] {
			t.Errorf("leaf attests %s %s, but that lookup failed", r.Type, r.Name)
		}
	}
	for _, r := range published {
		if !inLeaf[r.Name+"|"+string(r.Type)+"|"+r.Value] {
			t.Errorf("leaf is missing %s %s, which verified fine", r.Type, r.Name)
		}
	}
	if len(attested) != len(published) {
		t.Errorf("leaf record count: got %d want %d", len(attested), len(published))
	}
}
