package handler_test

// Integration tests for the identity event family through the full
// TL HTTP surface: the /v1/internal/identities/event ingest lane,
// the identity badge/audit/receipt/agents reads, the agent badge's
// computed identities[] join, and the cross-lane guards.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
	receiptpkg "github.com/godaddy/ans/internal/tl/receipt"
)

const testIdentityID = "01HXKQTESTIDENTITY0000000A"

// identityInner returns a valid identity event of the given type,
// keyed to the testbed's identity fixture. timestamps vary per call
// site so dedup never collides across events in one test; proof
// events name their verification method by the given kid so the
// read-join's provenKeyIds visibly flips on rotation.
func identityInner(typ identityevent.Type, ts string, ansIDs []string, kid string) identityevent.Event {
	ev := identityevent.Event{
		EventType:  typ,
		IdentityID: testIdentityID,
		Kind:       "did:web",
		Value:      "did:web:identity.acme-corp.com",
		RaID:       "ra-test-1",
		Timestamp:  ts,
	}
	switch typ {
	case identityevent.TypeIdentityVerified, identityevent.TypeIdentityUpdated:
		ev.ProviderID = "PID-1"
		ev.ProofMethod = "did-web-sig"
		ev.VerifiedAt = ts
		ev.Keys = []identityevent.ProvenKey{{
			VerificationMethod: json.RawMessage(`{"id":"` + kid + `","type":"JsonWebKey2020","controller":"did:web:identity.acme-corp.com","publicKeyJwk":{"crv":"Ed25519","kty":"OKP","x":"abc"}}`),
			SignedProof:        "eyJhbGciOiJFZERTQSJ9.p.s",
		}}
	case identityevent.TypeIdentityRevoked:
		ev.RevokedAt = ts
	case identityevent.TypeIdentityLinked, identityevent.TypeIdentityUnlinked:
		ev.AnsIDs = ansIDs
	}
	return ev
}

// postIdentityEvent signs and posts an identity event body to the
// identity ingest lane, asserting 200.
func postIdentityEvent(t *testing.T, tb *tlTestbed, ev identityevent.Event) {
	t.Helper()
	body := []byte(mustJSON(t, ev))
	rec := tb.postTo(t, "/v1/internal/identities/event", body, tb.signWithProducer(t, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("identity ingest: got %d, body=%s", rec.Code, rec.Body)
	}
}

func getJSON(t *testing.T, tb *tlTestbed, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v (body=%s)", path, err, rec.Body)
		}
	}
	return rec.Code
}

// badgeView decodes the subset of the badge/audit responses the
// tests assert on.
type badgeView struct {
	SchemaVersion string `json:"schemaVersion"`
	Status        string `json:"status"`
	Signature     string `json:"signature"`
	Identities    []struct {
		IdentityID     string   `json:"identityId"`
		Kind           string   `json:"kind"`
		Value          string   `json:"value"`
		IdentityStatus string   `json:"identityStatus"`
		ProvenKeyIDs   []string `json:"provenKeyIds"`
		LinkedAt       string   `json:"linkedAt"`
		LinkLogID      string   `json:"linkLogId"`
		IdentityLogID  string   `json:"identityLogId"`
	} `json:"identities"`
}

// auditView decodes the subset of audit responses the stages assert
// on.
type auditView struct {
	Records []struct {
		Payload struct {
			Producer struct {
				Event struct {
					EventType string `json:"eventType"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	} `json:"records"`
}

// TestIdentityLifecycle_EndToEnd drives the whole identity read
// surface through real ingests: verify → link → rotate → revoke →
// unlink, asserting the computed joins after each stage.
func TestIdentityLifecycle_EndToEnd(t *testing.T) {
	tb := newTLTestbed(t)

	// Seed the agent the identity will link to (the testbed's agent
	// fixture) so the agent badge exists.
	agentBody := []byte(mustJSON(t, tb.inner))
	tb.postEvent(t, agentBody, tb.signWithProducer(t, agentBody))
	agentID := tb.inner.AnsID

	stageVerify(t, tb, agentID)
	stageLink(t, tb, agentID)
	stageRotate(t, tb, agentID)
	stageRevoke(t, tb, agentID)
	stageUnlink(t, tb, agentID)
}

// stageVerify seals IDENTITY_VERIFIED and checks the identity badge
// plus the (still identity-free) agent badge.
func stageVerify(t *testing.T, tb *tlTestbed, agentID string) {
	t.Helper()
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityVerified, "2026-06-10T10:00:00Z", nil, "did:web:identity.acme-corp.com#key-1"))

	var idBadge badgeView
	if code := getJSON(t, tb, "/v1/identities/"+testIdentityID, &idBadge); code != http.StatusOK {
		t.Fatalf("identity badge: %d", code)
	}
	if idBadge.Status != "VERIFIED" {
		t.Fatalf("identity status = %q, want VERIFIED", idBadge.Status)
	}
	if idBadge.SchemaVersion != "V2" || idBadge.Signature == "" {
		t.Fatalf("identity badge missing schema/attestation: %+v", idBadge)
	}

	var agentBadge badgeView
	if code := getJSON(t, tb, "/v1/agents/"+agentID, &agentBadge); code != http.StatusOK {
		t.Fatalf("agent badge: %d", code)
	}
	if len(agentBadge.Identities) != 0 {
		t.Fatalf("agent badge identities before link: %+v", agentBadge.Identities)
	}
}

// stageLink seals IDENTITY_LINKED and checks the join in both
// directions.
func stageLink(t *testing.T, tb *tlTestbed, agentID string) {
	t.Helper()
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityLinked, "2026-06-10T11:00:00Z", []string{agentID}, ""))

	var agentBadge badgeView
	if code := getJSON(t, tb, "/v1/agents/"+agentID, &agentBadge); code != http.StatusOK {
		t.Fatalf("agent badge after link: %d", code)
	}
	if len(agentBadge.Identities) != 1 {
		t.Fatalf("agent badge identities after link: %+v", agentBadge.Identities)
	}
	got := agentBadge.Identities[0]
	if got.IdentityID != testIdentityID || got.IdentityStatus != "VERIFIED" ||
		got.Kind != "did:web" || got.Value != "did:web:identity.acme-corp.com" {
		t.Fatalf("join entry wrong: %+v", got)
	}
	if len(got.ProvenKeyIDs) != 1 || got.ProvenKeyIDs[0] != "did:web:identity.acme-corp.com#key-1" {
		t.Fatalf("provenKeyIds = %v", got.ProvenKeyIDs)
	}
	if got.LinkedAt != "2026-06-10T11:00:00Z" || got.LinkLogID == "" || got.IdentityLogID == "" {
		t.Fatalf("link evidence fields missing: %+v", got)
	}

	// The standalone computed view matches the badge join.
	var identitiesResp struct {
		Identities []json.RawMessage `json:"identities"`
	}
	if code := getJSON(t, tb, "/v1/agents/"+agentID+"/identities", &identitiesResp); code != http.StatusOK {
		t.Fatalf("agent identities view: %d", code)
	}
	if len(identitiesResp.Identities) != 1 {
		t.Fatalf("agent identities view count = %d", len(identitiesResp.Identities))
	}

	// Reverse join: identity → agents, with the agent's own status.
	var agentsResp struct {
		Agents []struct {
			AnsID       string `json:"ansId"`
			AgentStatus string `json:"agentStatus"`
			LinkedAt    string `json:"linkedAt"`
		} `json:"agents"`
	}
	if code := getJSON(t, tb, "/v1/identities/"+testIdentityID+"/agents", &agentsResp); code != http.StatusOK {
		t.Fatalf("identity agents view: %d", code)
	}
	if len(agentsResp.Agents) != 1 || agentsResp.Agents[0].AnsID != agentID ||
		agentsResp.Agents[0].AgentStatus != "ACTIVE" {
		t.Fatalf("reverse join: %+v", agentsResp.Agents)
	}
}

// stageRotate seals IDENTITY_UPDATED and checks the proven-key flip
// plus the stream-purity invariants on both audits.
func stageRotate(t *testing.T, tb *tlTestbed, agentID string) {
	t.Helper()
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityUpdated, "2026-06-10T12:00:00Z", nil, "did:web:identity.acme-corp.com#key-2"))

	var agentBadge badgeView
	if code := getJSON(t, tb, "/v1/agents/"+agentID, &agentBadge); code != http.StatusOK {
		t.Fatalf("agent badge after rotation: %d", code)
	}
	if ids := agentBadge.Identities[0].ProvenKeyIDs; len(ids) != 1 || ids[0] != "did:web:identity.acme-corp.com#key-2" {
		t.Fatalf("rotation not visible on linked badge: %v", ids)
	}

	// The agent's own audit history stays purely AGENT_* — identity
	// operations never write to the agent stream.
	var audit auditView
	if code := getJSON(t, tb, "/v1/agents/"+agentID+"/audit", &audit); code != http.StatusOK {
		t.Fatalf("agent audit: %d", code)
	}
	if len(audit.Records) != 1 || audit.Records[0].Payload.Producer.Event.EventType != "AGENT_REGISTERED" {
		t.Fatalf("agent audit polluted by identity ops: %+v", audit.Records)
	}

	// Identity audit carries the full chain, newest first.
	if code := getJSON(t, tb, "/v1/identities/"+testIdentityID+"/audit", &audit); code != http.StatusOK {
		t.Fatalf("identity audit: %d", code)
	}
	if len(audit.Records) != 3 {
		t.Fatalf("identity audit count = %d, want 3", len(audit.Records))
	}
	if audit.Records[0].Payload.Producer.Event.EventType != "IDENTITY_UPDATED" {
		t.Fatalf("identity audit order: %+v", audit.Records[0])
	}

	// Association history for the agent: the standard audit envelope
	// filtered to link events naming it.
	if code := getJSON(t, tb, "/v1/agents/"+agentID+"/identities/history", &audit); code != http.StatusOK {
		t.Fatalf("identity history: %d", code)
	}
	if len(audit.Records) != 1 || audit.Records[0].Payload.Producer.Event.EventType != "IDENTITY_LINKED" {
		t.Fatalf("identity history: %+v", audit.Records)
	}
}

// stageRevoke seals IDENTITY_REVOKED: one event, every linked badge
// reflects it; the agent itself is untouched.
func stageRevoke(t *testing.T, tb *tlTestbed, agentID string) {
	t.Helper()
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityRevoked, "2026-06-10T13:00:00Z", nil, ""))

	var idBadge badgeView
	if code := getJSON(t, tb, "/v1/identities/"+testIdentityID, &idBadge); code != http.StatusOK {
		t.Fatalf("identity badge after revoke: %d", code)
	}
	if idBadge.Status != "REVOKED" {
		t.Fatalf("identity status after revoke = %q", idBadge.Status)
	}
	var agentBadge badgeView
	if code := getJSON(t, tb, "/v1/agents/"+agentID, &agentBadge); code != http.StatusOK {
		t.Fatalf("agent badge after revoke: %d", code)
	}
	if len(agentBadge.Identities) != 1 || agentBadge.Identities[0].IdentityStatus != "REVOKED" {
		t.Fatalf("revocation not visible on linked badge: %+v", agentBadge.Identities)
	}
	// The agent itself is untouched (the what survives the who's
	// revocation, and vice versa).
	if agentBadge.Status != "ACTIVE" {
		t.Fatalf("agent status changed by identity revocation: %s", agentBadge.Status)
	}
}

// stageUnlink seals IDENTITY_UNLINKED: the computed views empty out,
// the history retains both link events.
func stageUnlink(t *testing.T, tb *tlTestbed, agentID string) {
	t.Helper()
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityUnlinked, "2026-06-10T14:00:00Z", []string{agentID}, ""))

	var unlinkedBadge badgeView
	if code := getJSON(t, tb, "/v1/agents/"+agentID, &unlinkedBadge); code != http.StatusOK {
		t.Fatalf("agent badge after unlink: %d", code)
	}
	if len(unlinkedBadge.Identities) != 0 {
		t.Fatalf("identities after unlink: %+v", unlinkedBadge.Identities)
	}
	var audit auditView
	if code := getJSON(t, tb, "/v1/agents/"+agentID+"/identities/history", &audit); code != http.StatusOK {
		t.Fatalf("identity history after unlink: %d", code)
	}
	if len(audit.Records) != 2 {
		t.Fatalf("identity history count after unlink = %d", len(audit.Records))
	}
}

// TestIdentityIngest_CrossLaneGuards pins the 422s in both
// directions: identity bodies on the agent lanes, agent bodies on
// the identity lane.
func TestIdentityIngest_CrossLaneGuards(t *testing.T) {
	tb := newTLTestbed(t)

	idBody := []byte(mustJSON(t, identityInner(
		identityevent.TypeIdentityVerified, "2026-06-10T10:00:00Z", nil, "did:web:identity.acme-corp.com#key-1")))

	// Identity body on the V2 agent lane → 422.
	if rec := tb.postTo(t, "/v2/internal/agents/event", idBody, tb.signWithProducer(t, idBody)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("identity body on V2 agent lane: got %d", rec.Code)
	}
	// Identity body on the frozen V1 lane → 422.
	if rec := tb.postTo(t, "/v1/internal/agents/event", idBody, tb.signWithProducer(t, idBody)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("identity body on V1 agent lane: got %d", rec.Code)
	}
	// Agent body on the identity lane → 422.
	agentBody := []byte(mustJSON(t, tb.inner))
	if rec := tb.postTo(t, "/v1/internal/identities/event", agentBody, tb.signWithProducer(t, agentBody)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("agent body on identity lane: got %d", rec.Code)
	}
	// Missing producer signature → 422.
	if rec := tb.postTo(t, "/v1/internal/identities/event", idBody, ""); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing signature on identity lane: got %d", rec.Code)
	}
}

// TestIdentityIngest_Duplicate pins idempotent retries on the
// identity lane: same canonical bytes → 200 + duplicate flag.
func TestIdentityIngest_Duplicate(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, identityInner(
		identityevent.TypeIdentityVerified, "2026-06-10T10:00:00Z", nil, "did:web:identity.acme-corp.com#key-1")))
	jws := tb.signWithProducer(t, body)

	first := tb.postTo(t, "/v1/internal/identities/event", body, jws)
	if first.Code != http.StatusOK {
		t.Fatalf("first append: %d body=%s", first.Code, first.Body)
	}
	second := tb.postTo(t, "/v1/internal/identities/event", body, jws)
	if second.Code != http.StatusOK {
		t.Fatalf("retry: %d", second.Code)
	}
	var resp struct {
		Duplicate bool   `json:"duplicate"`
		Message   string `json:"message"`
	}
	_ = json.Unmarshal(second.Body.Bytes(), &resp)
	if !resp.Duplicate || resp.Message != "Event already logged" {
		t.Fatalf("retry not flagged duplicate: %+v", resp)
	}
}

// TestIdentityReceipt verifies the identity receipt is a real
// COSE_Sign1 that offline-verifies against the TL's public key.
func TestIdentityReceipt(t *testing.T) {
	tb := newTLTestbed(t)
	postIdentityEvent(t, tb,
		identityInner(identityevent.TypeIdentityVerified, "2026-06-10T10:00:00Z", nil, "did:web:identity.acme-corp.com#key-1"))

	var rec *httptest.ResponseRecorder
	for range 50 {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/identities/"+testIdentityID+"/receipt", nil)
		tb.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("never got 200; last status=%d body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != receiptpkg.MediaType {
		t.Errorf("content-type: got %q want %q", ct, receiptpkg.MediaType)
	}
	if err := receiptpkg.VerifyWithPEM(rec.Body.Bytes(), string(tb.signPubPEM)); err != nil {
		t.Errorf("offline verify: %v", err)
	}
}

// TestIdentityReads_NotFound pins 404s for unknown identities across
// the read surface.
func TestIdentityReads_NotFound(t *testing.T) {
	tb := newTLTestbed(t)
	for _, path := range []string{
		"/v1/identities/unknown-id",
		"/v1/identities/unknown-id/receipt",
		"/v1/identities/unknown-id/agents",
	} {
		if code := getJSON(t, tb, path, nil); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, code)
		}
	}
	// Audit and the agent-side views are list-shaped: empty lists.
	var audit struct {
		Records []json.RawMessage `json:"records"`
	}
	if code := getJSON(t, tb, "/v1/identities/unknown-id/audit", &audit); code != http.StatusOK || len(audit.Records) != 0 {
		t.Errorf("unknown identity audit: code=%d records=%d", code, len(audit.Records))
	}
}
