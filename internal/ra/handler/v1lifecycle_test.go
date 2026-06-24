package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// V1 lifecycle tests. Every transition that produces a TL leaf is
// checked at BOTH the HTTP-shape level (response fields match the
// reference spec) AND the outbox-lane level (schema_version=V1,
// event_type matches the V1 terminal enum).

// TestV1VerifyACME_AdvancesStateNoTLEmit exercises the V1 behavior
// where ACME validation advances the domain state to PENDING_DNS but
// writes no TL leaf. V1's TL enum has no intermediate
// DOMAIN_VALIDATION type.
func TestV1VerifyACME_AdvancesStateNoTLEmit(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	// Snapshot outbox before verify-acme so we can diff afterwards.
	rowsBefore, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	countBefore := len(rowsBefore)

	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	// State advanced to PENDING_DNS.
	detail := fx.request(t, http.MethodGet, "/v1/agents/"+agentID, nil, fx.asOwner("alice"))
	var d struct {
		AgentStatus string `json:"agentStatus"`
	}
	_ = json.Unmarshal(detail.Body.Bytes(), &d)
	if d.AgentStatus != "PENDING_DNS" {
		t.Errorf("agent status: got %q, want PENDING_DNS", d.AgentStatus)
	}

	// No new outbox rows — V1 verify-acme is a no-op on the TL.
	rowsAfter, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsAfter) != countBefore {
		t.Errorf("V1 verify-acme should not add outbox rows: before=%d after=%d",
			countBefore, len(rowsAfter))
	}
}

// TestV1VerifyDNS_EmitsAgentRegistered is the V1 lifecycle's FIRST
// real TL emit. After DNS verify succeeds, V1 writes an
// AGENT_REGISTERED envelope stamped with schema_version=V1.
func TestV1VerifyDNS_EmitsAgentRegistered(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	// Walk through verify-acme first — required precondition for
	// verify-dns (PENDING_DNS state).
	ack := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	if ack.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", ack.Code, ack.Body)
	}

	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("verify-dns status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse verify-dns: %v", err)
	}
	if resp.Status != "ACTIVE" {
		t.Errorf("status: got %q, want ACTIVE", resp.Status)
	}

	// AGENT_REGISTERED seals INLINE at the verify-dns ACTIVE transition
	// (seal-before-success), stamped schema_version=V1 — not enqueued
	// to the outbox. Earlier steps (register + verify-acme) must not
	// have sealed anything, because V1 emits only on terminal
	// transitions. The outbox must stay empty for this lifecycle.
	var registered int
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion != "V1" {
			t.Errorf("V1 agent sealed event schema_version=%q, want V1", s.SchemaVersion)
		}
		if s.EventType == "AGENT_REGISTERED" {
			registered++
		}
	}
	if registered != 1 {
		t.Errorf("V1 lifecycle must seal exactly one AGENT_REGISTERED leaf; got %d", registered)
	}
	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("activation seals inline; outbox must be empty, got %d rows", len(rows))
	}
}

// TestV1VerifyDNS_EmitsFullAttestations pins the V1 AGENT_REGISTERED
// attestation block byte-shape-for-byte against the reference V1
// RA-attestations schema. Every V1 agent's first TL leaf must carry:
//
//   - `dnsRecordsProvisioned` as a map[name]data (V1 lossy shape —
//     one value per owner name).
//   - `domainValidation: "ACME-DNS-01"` (reference constant).
//   - `identityCert` singleton object with `fingerprint` + `type`.
//   - `validIdentityCerts[]` rotation array carrying the same cert
//     plus a `notAfter` timestamp. V1 emits this array even in the
//     single-cert case (matches reference behavior).
//
// Regression guard against the pre-fix state where the V1 service
// emitted AGENT_REGISTERED with NO attestations at all.
func TestV1VerifyDNS_EmitsFullAttestations(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	if ack := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice")); ack.Code != http.StatusAccepted {
		t.Fatalf("verify-dns: %d %s", ack.Code, ack.Body)
	}

	// AGENT_REGISTERED seals inline at activation; pull the sealed V1
	// event and drill into its attestation block. The sealer records
	// the JCS-canonical inner-event bytes the RA signed — the same
	// bytes posted to the TL — so there is no {innerEventCanonical,
	// producerSignature} outbox wrapper to unwrap here.
	var innerCanonical []byte
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion == "V1" && s.EventType == "AGENT_REGISTERED" {
			innerCanonical = s.InnerCanonical
		}
	}
	if len(innerCanonical) == 0 {
		t.Fatal("no AGENT_REGISTERED sealed event found")
	}
	var inner struct {
		EventType    string `json:"eventType"`
		Attestations struct {
			DNSRecordsProvisioned map[string]string `json:"dnsRecordsProvisioned"`
			DomainValidation      string            `json:"domainValidation"`
			IdentityCert          *struct {
				Fingerprint string `json:"fingerprint"`
				Type        string `json:"type"`
			} `json:"identityCert"`
			ValidIdentityCerts []struct {
				Fingerprint string `json:"fingerprint"`
				Type        string `json:"type"`
				NotAfter    string `json:"notAfter"`
			} `json:"validIdentityCerts"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(innerCanonical, &inner); err != nil {
		t.Fatalf("unmarshal inner event: %v", err)
	}

	if inner.EventType != "AGENT_REGISTERED" {
		t.Errorf("eventType: got %q, want AGENT_REGISTERED", inner.EventType)
	}
	if inner.Attestations.DomainValidation != "ACME-DNS-01" {
		t.Errorf("domainValidation: got %q, want ACME-DNS-01", inner.Attestations.DomainValidation)
	}
	if len(inner.Attestations.DNSRecordsProvisioned) == 0 {
		t.Error("dnsRecordsProvisioned must be populated")
	}
	// Expected DNS records for agent.example.com v1.0.0: _ans TXT,
	// _ans-badge TXT. TLSA too when a server cert is present (none
	// in this test). We assert presence of the two guaranteed ones.
	if _, ok := inner.Attestations.DNSRecordsProvisioned["_ans.agent.example.com"]; !ok {
		t.Errorf("missing _ans TXT in dnsRecordsProvisioned: %v", inner.Attestations.DNSRecordsProvisioned)
	}
	if _, ok := inner.Attestations.DNSRecordsProvisioned["_ans-badge.agent.example.com"]; !ok {
		t.Errorf("missing _ans-badge TXT in dnsRecordsProvisioned: %v", inner.Attestations.DNSRecordsProvisioned)
	}
	if inner.Attestations.IdentityCert == nil {
		t.Fatal("identityCert (singleton) must be populated")
	}
	if !strings.HasPrefix(inner.Attestations.IdentityCert.Fingerprint, "SHA256:") {
		t.Errorf("identityCert.fingerprint should start SHA256:, got %q", inner.Attestations.IdentityCert.Fingerprint)
	}
	if inner.Attestations.IdentityCert.Type != "X509-OV-CLIENT" {
		t.Errorf("identityCert.type: got %q, want X509-OV-CLIENT", inner.Attestations.IdentityCert.Type)
	}
	if len(inner.Attestations.ValidIdentityCerts) != 1 {
		t.Errorf("validIdentityCerts: got %d, want exactly 1 at registration time",
			len(inner.Attestations.ValidIdentityCerts))
	} else {
		if inner.Attestations.ValidIdentityCerts[0].Fingerprint != inner.Attestations.IdentityCert.Fingerprint {
			t.Error("validIdentityCerts[0].fingerprint must match identityCert.fingerprint")
		}
		if inner.Attestations.ValidIdentityCerts[0].NotAfter == "" {
			t.Error("validIdentityCerts[0].notAfter must be populated (RFC3339 timestamp)")
		}
	}
}

// TestV1Revoke_EmitsAttestations pins the V1 AGENT_REVOKED
// attestation block: revokedAt timestamp, reason code, cert
// fingerprints being revoked, and DNS records to tear down. Matches
// the reference V1 RA-attestations schema.
func TestV1Revoke_EmitsAttestations(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))

	revBody, _ := json.Marshal(map[string]any{"reason": "KEY_COMPROMISE"})
	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/revoke",
		bytes.NewReader(revBody), fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}

	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var payloadJSON []byte
	for _, row := range rows {
		if row.AgentID == agentID && row.EventType == "AGENT_REVOKED" {
			payloadJSON = row.PayloadJSON
		}
	}
	if len(payloadJSON) == 0 {
		t.Fatal("no AGENT_REVOKED outbox row found")
	}
	var payload struct {
		InnerEventCanonical json.RawMessage `json:"innerEventCanonical"`
	}
	_ = json.Unmarshal(payloadJSON, &payload)
	var inner struct {
		EventType            string `json:"eventType"`
		RevocationReasonCode string `json:"revocationReasonCode"`
		RevokedAt            string `json:"revokedAt"`
		Attestations         struct {
			DNSRecordsProvisioned map[string]string `json:"dnsRecordsProvisioned"`
			ValidIdentityCerts    []struct {
				Fingerprint string `json:"fingerprint"`
				Type        string `json:"type"`
				NotAfter    string `json:"notAfter"`
			} `json:"validIdentityCerts"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(payload.InnerEventCanonical, &inner); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}

	if inner.EventType != "AGENT_REVOKED" {
		t.Errorf("eventType: got %q, want AGENT_REVOKED", inner.EventType)
	}
	if inner.RevocationReasonCode != "KEY_COMPROMISE" {
		t.Errorf("revocationReasonCode: got %q, want KEY_COMPROMISE", inner.RevocationReasonCode)
	}
	if inner.RevokedAt == "" {
		t.Error("revokedAt must be set")
	}
	if len(inner.Attestations.DNSRecordsProvisioned) == 0 {
		t.Error("dnsRecordsProvisioned must list records to tear down")
	}
	if len(inner.Attestations.ValidIdentityCerts) == 0 {
		t.Error("validIdentityCerts must list revoked cert fingerprints")
	}
	for i, c := range inner.Attestations.ValidIdentityCerts {
		if !strings.HasPrefix(c.Fingerprint, "SHA256:") {
			t.Errorf("validIdentityCerts[%d].fingerprint: %q", i, c.Fingerprint)
		}
		if c.NotAfter == "" {
			t.Errorf("validIdentityCerts[%d].notAfter missing", i)
		}
	}
}

// TestV1Revoke_EmitsAgentRevoked drives the revocation flow and pins
// both the HTTP response shape (AgentRevocationResponse byte-for-byte
// parity) and the outbox emission (AGENT_REVOKED event stamped V1).
func TestV1Revoke_EmitsAgentRevoked(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	// Agent must be ACTIVE to revoke — drive through the lifecycle.
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	ack := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))
	if ack.Code != http.StatusAccepted {
		t.Fatalf("verify-dns: %d %s", ack.Code, ack.Body)
	}

	revBody, _ := json.Marshal(map[string]any{
		"reason":   "KEY_COMPROMISE",
		"comments": "rotating compromised key",
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/revoke",
		bytes.NewReader(revBody), fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rec.Code, rec.Body)
	}

	var resp struct {
		AgentID   string `json:"agentId"`
		Status    string `json:"status"`
		Reason    string `json:"reason"`
		RevokedAt string `json:"revokedAt"`
		Links     []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse revoke: %v", err)
	}
	if resp.AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.AgentID, agentID)
	}
	if resp.Status != "REVOKED" {
		t.Errorf("status: got %q want REVOKED", resp.Status)
	}
	if resp.Reason != "KEY_COMPROMISE" {
		t.Errorf("reason: got %q", resp.Reason)
	}
	if resp.RevokedAt == "" {
		t.Error("revokedAt missing")
	}
	if len(resp.Links) == 0 || !strings.Contains(resp.Links[0].Href, "/v1/agents/"+agentID) {
		t.Errorf("self link must be on /v1/, got %+v", resp.Links)
	}

	// Outbox: AGENT_REVOKED V1 envelope present.
	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var foundRevoked bool
	for _, row := range rows {
		if row.AgentID != agentID {
			continue
		}
		if row.EventType == "AGENT_REVOKED" {
			foundRevoked = true
			if row.SchemaVersion != "V1" {
				t.Errorf("revoked row schema_version=%q, want V1", row.SchemaVersion)
			}
		}
	}
	if !foundRevoked {
		t.Error("outbox missing AGENT_REVOKED row after V1 revoke")
	}
}

// TestV1Revoke_MissingReason_422 confirms the handler enforces the
// required `reason` field per reference spec.
func TestV1Revoke_MissingReason_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte(`{}`)), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "MISSING_REASON") {
		t.Errorf("expected MISSING_REASON code, got %s", rec.Body)
	}
}

// TestV1Revoke_NotOwned_403 confirms WriteOwnership 403 on
// not-owned revoke attempts (as opposed to read routes which 404).
func TestV1Revoke_NotOwned_403(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	revBody, _ := json.Marshal(map[string]string{"reason": "KEY_COMPROMISE"})
	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/revoke",
		bytes.NewReader(revBody), fx.asOwner("bob"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d body=%s", rec.Code, rec.Body)
	}
}
