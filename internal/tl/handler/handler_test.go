package handler_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
	"github.com/agentnameservice/ans/internal/tl/handler"
	"github.com/agentnameservice/ans/internal/tl/logstore"
	"github.com/agentnameservice/ans/internal/tl/producerkey"
	receiptpkg "github.com/agentnameservice/ans/internal/tl/receipt"
	"github.com/agentnameservice/ans/internal/tl/service"
)

// TestAppendEvent is the full RA → TL ingest smoke test. If this
// passes, the whole new pipeline works: producer signs, TL verifies,
// envelope builds, TL signs, Tessera appends, SQLite stores, handler
// returns 200 with the reference's {logId, message, success} shape
// alongside ans-specific leaf metadata.
func TestAppendEvent_HappyPath(t *testing.T) {
	tb := newTLTestbed(t)

	body := []byte(mustJSON(t, tb.inner))
	jws := tb.signWithProducer(t, body)

	rec := tb.postEvent(t, body, jws)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body)
	}

	var resp struct {
		LogID     string `json:"logId"`
		Message   string `json:"message"`
		Success   bool   `json:"success"`
		LeafIndex uint64 `json:"leafIndex"`
		LeafHash  string `json:"leafHashHex"`
		Duplicate bool   `json:"duplicate"`
		TreeSize  uint64 `json:"treeSize"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v (body: %s)", err, rec.Body)
	}
	if resp.LogID == "" {
		t.Error("logId: want non-empty UUID on first append")
	}
	if resp.Message != "Event logged successfully" {
		t.Errorf("message: got %q, want %q", resp.Message, "Event logged successfully")
	}
	if !resp.Success {
		t.Error("success: want true on new-append 200")
	}
	if resp.LeafIndex != 0 {
		t.Errorf("leafIndex: got %d, want 0", resp.LeafIndex)
	}
	if resp.Duplicate {
		t.Error("first append should not be duplicate")
	}
	if len(resp.LeafHash) != 64 {
		t.Errorf("leaf hash should be 64 hex chars, got %d", len(resp.LeafHash))
	}
}

func TestAppendEvent_IdempotentRetry(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	jws := tb.signWithProducer(t, body)

	first := tb.postEvent(t, body, jws)
	if first.Code != http.StatusOK {
		t.Fatalf("first append: got %d, body=%s", first.Code, first.Body)
	}
	var firstResp struct {
		LogID string `json:"logId"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &firstResp)

	// Re-send the identical body + JWS. Content hash matches → 200 OK
	// with same leaf index + same logId, marked duplicate. Reference
	// parity: `message` flips to "Event already logged".
	second := tb.postEvent(t, body, jws)
	if second.Code != http.StatusOK {
		t.Fatalf("retry: got %d, body=%s", second.Code, second.Body)
	}
	var resp struct {
		LogID     string `json:"logId"`
		Message   string `json:"message"`
		Success   bool   `json:"success"`
		Duplicate bool   `json:"duplicate"`
		LeafIndex uint64 `json:"leafIndex"`
	}
	_ = json.Unmarshal(second.Body.Bytes(), &resp)
	if !resp.Duplicate {
		t.Error("retry should be flagged duplicate")
	}
	if !resp.Success {
		t.Error("success: duplicate retry should still report success=true")
	}
	if resp.Message != "Event already logged" {
		t.Errorf("duplicate message: got %q, want %q", resp.Message, "Event already logged")
	}
	if resp.LogID != firstResp.LogID {
		t.Errorf("logId on duplicate: got %q, want %q (same as first)", resp.LogID, firstResp.LogID)
	}
	if resp.LeafIndex != 0 {
		t.Errorf("leaf index should point to original 0, got %d", resp.LeafIndex)
	}
}

func TestAppendEvent_MissingXSignature(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	rec := tb.postEvent(t, body, "") // no X-Signature
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "NO_PRODUCER_SIGNATURE")
}

func TestAppendEvent_BadSignatureHeader(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	rec := tb.postEvent(t, body, "not.a.jws")
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "INVALID_SIGNATURE_HEADER")
}

func TestAppendEvent_UnknownProducerKey(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	// Sign with a fresh key that isn't registered.
	strangerKM, _ := newSignerKM(t, "stranger")
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), strangerKM, "stranger",
		anscrypto.JWSProtectedHeader{RAID: "ra-stranger"},
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := tb.postEvent(t, body, jws)
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "NOT_FOUND_PRODUCER_KEY")
}

func TestAppendEvent_TamperedBody(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	jws := tb.signWithProducer(t, body)
	// Change a field → signature no longer verifies.
	tampered := bytes.Replace(body, []byte("AGENT_REGISTERED"), []byte("AGENT_REVOKED"), 1)
	rec := tb.postEvent(t, tampered, jws)
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "MISMATCH_SIGNATURE")
}

func TestAppendEvent_RAIDMismatch(t *testing.T) {
	tb := newTLTestbed(t)
	inner := tb.inner
	inner.RaID = "ra-different" // signed-header says ra-test-1
	body := []byte(mustJSON(t, &inner))
	jws := tb.signWithProducer(t, body)
	rec := tb.postEvent(t, body, jws)
	// Must match the RAID in the JWS header (ra-test-1) — body says
	// ra-different, signed-header says ra-test-1 → RAID_MISMATCH 422.
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "RAID_MISMATCH")
}

func TestAppendEvent_InvalidEvent_MissingRequiredFields(t *testing.T) {
	tb := newTLTestbed(t)
	// Valid JSON, signable, but missing fields our Event.Validate() requires.
	body := []byte(`{"ansId":"a"}`) // missing eventType, ansName, timestamp
	jws := tb.signWithProducer(t, body)
	rec := tb.postEvent(t, body, jws)
	// The sig verifies fine (body is valid JSON, canonicalizes OK) but
	// Event.Validate() rejects; we get 422 INVALID_EVENT.
	assertStatusAndCode(t, rec, http.StatusUnprocessableEntity, "INVALID_EVENT")
}

func TestAppendEvent_BodyTooLarge(t *testing.T) {
	tb := newTLTestbed(t)
	// Build a valid-shaped event whose canonical serialization exceeds
	// the 256 KiB limit. A 300 KiB `agentDescription` field inside the
	// Event's ansName is the simplest way; but since we don't have an
	// unbounded string field, just pad a field the shape allows. The
	// Event struct's strings have no length limit, so we'll pad
	// AgentFQDN via a raw JSON body that shapes to valid inner-event
	// json.
	big := make([]byte, 300*1024)
	for i := range big {
		big[i] = 'x'
	}
	body := []byte(`{"ansId":"a","ansName":"ans://v1.0.0.a.example.com","eventType":"AGENT_REGISTRATION","timestamp":"2026-01-01T00:00:00Z","agent":{"host":"` + string(big) + `","name":"x","version":"1"}}`)
	// Sig doesn't matter — MaxBytesReader trips inside io.ReadAll
	// before the service runs.
	rec := tb.postEvent(t, body, "dummy..sig")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 (Payload Too Large), got %d body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "BODY_TOO_LARGE" || prob.Status != 413 {
		t.Fatalf("problem body wrong: %+v", prob)
	}
}

// TestAppendEvent_TLAttestationTimestamp pins the WithClock hook: the
// TL attestation JWS emitted during Append reflects the service's
// configured nowFn. This exists because nowFn was wired but uncovered
// — the code-review pass flagged that a regression to e.g. UnixMilli
// would slip through unnoticed.
func TestAppendEvent_TLAttestationTimestamp(t *testing.T) {
	tb := newTLTestbed(t)
	fixed := time.Unix(1700000000, 0).UTC()
	tb.logSvc.WithClock(func() time.Time { return fixed })

	body := []byte(mustJSON(t, tb.inner))
	jws := tb.signWithProducer(t, body)
	rec := tb.postEvent(t, body, jws)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	// Pull the stored envelope back and inspect the outer signature's
	// JCS'd header — the timestamp there must match our fixed clock.
	stored, err := tb.eventStore.GetEventByLeafIndex(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	env, err := stored.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	header, err := anscrypto.DecodeHeader(env.Signature)
	if err != nil {
		t.Fatalf("decode TL attestation header: %v", err)
	}
	if header.Timestamp != fixed.Unix() {
		t.Fatalf("TL attestation timestamp: got %d, want %d (clock override broken)",
			header.Timestamp, fixed.Unix())
	}
}

// ----- badge / audit / receipt endpoints -----

func TestGetBadge(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	tb.postEvent(t, body, tb.signWithProducer(t, body))

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/"+tb.inner.AnsID, nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body)
	}
	// Response is reference-shaped TransparencyLog:
	//   { merkleProof?, payload, schemaVersion, signature?, status }
	var resp struct {
		MerkleProof *struct{} `json:"merkleProof"`
		Payload     *struct {
			LogID    string `json:"logId"`
			Producer *struct {
				Event *struct {
					AnsID   string `json:"ansId"`
					AnsName string `json:"ansName"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
		SchemaVersion string `json:"schemaVersion"`
		Signature     string `json:"signature"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v body=%s", err, rec.Body)
	}
	if resp.Status != "ACTIVE" {
		t.Fatalf("status: got %q want ACTIVE", resp.Status)
	}
	if resp.SchemaVersion != "V2" {
		t.Fatalf("schemaVersion: got %q want V2", resp.SchemaVersion)
	}
	if resp.Signature == "" {
		t.Error("signature (TL attestation) missing")
	}
	if resp.Payload == nil || resp.Payload.Producer == nil || resp.Payload.Producer.Event == nil {
		t.Fatalf("payload.producer.event missing: %s", rec.Body)
	}
	if resp.Payload.Producer.Event.AnsID != tb.inner.AnsID {
		t.Errorf("payload.producer.event.ansId: got %q want %q",
			resp.Payload.Producer.Event.AnsID, tb.inner.AnsID)
	}
}

func TestGetBadge_MissingAgentID(t *testing.T) {
	tb := newTLTestbed(t)
	// Unknown agent → 404 not-found from the store layer.
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/does-not-exist", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404; body=%s", rec.Code, rec.Body)
	}
}

func TestGetAudit(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	tb.postEvent(t, body, tb.signWithProducer(t, body))

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/"+tb.inner.AnsID+"/audit?limit=10", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body)
	}
	// Response shape: { "records": [TransparencyLog, ...] }
	var resp struct {
		Records []struct {
			SchemaVersion string `json:"schemaVersion"`
			Signature     string `json:"signature"`
			Status        string `json:"status"`
			Payload       struct {
				LogID    string `json:"logId"`
				Producer struct {
					Event struct {
						EventType string `json:"eventType"`
					} `json:"event"`
				} `json:"producer"`
			} `json:"payload"`
		} `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("want 1 record, got %d body=%s", len(resp.Records), rec.Body)
	}
	if resp.Records[0].Payload.Producer.Event.EventType != "AGENT_REGISTERED" {
		t.Errorf("eventType: got %q", resp.Records[0].Payload.Producer.Event.EventType)
	}
	if resp.Records[0].SchemaVersion != "V2" {
		t.Errorf("schemaVersion: got %q", resp.Records[0].SchemaVersion)
	}
	if resp.Records[0].Signature == "" {
		t.Error("TL attestation signature missing")
	}
}

// TestGetReceipt_200_PollsUntilCovered explicitly drives the
// success arm of GetReceipt by polling until the checkpoint covers
// the appended leaf. Pre-coverage the existing test sometimes
// landed in the 200 branch and sometimes the 503 branch depending
// on timing, leaving the "emit receipt bytes" path (lines 282-287)
// non-deterministically dark. This run loops until 200 lands and
// asserts the receipt round-trips through the offline verifier.
func TestGetReceipt_200_PollsUntilCovered(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	tb.postEvent(t, body, tb.signWithProducer(t, body))

	var rec *httptest.ResponseRecorder
	for range 50 {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/agents/"+tb.inner.AnsID+"/receipt", nil)
		tb.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("never got 200; last status=%d body=%s", rec.Code, rec.Body)
	}
	// Headers and body shape match the contract.
	if ct := rec.Header().Get("Content-Type"); ct != receiptpkg.MediaType {
		t.Errorf("content-type: got %q want %q", ct, receiptpkg.MediaType)
	}
	if rec.Body.Len() == 0 {
		t.Error("body is empty")
	}
	if err := receiptpkg.VerifyWithPEM(rec.Body.Bytes(), string(tb.signPubPEM)); err != nil {
		t.Errorf("offline verify: %v", err)
	}
}

func TestGetReceipt_503UntilCheckpoint(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	tb.postEvent(t, body, tb.signWithProducer(t, body))

	// Hit receipt before Tessera has sealed a checkpoint.
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/"+tb.inner.AnsID+"/receipt", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	// Either 200 (checkpoint already sealed the leaf thanks to short
	// BatchMaxAge) or 503 with Retry-After. Both are valid behaviors.
	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body)
	}
	if rec.Code == http.StatusServiceUnavailable {
		if ra := rec.Header().Get("Retry-After"); ra == "" {
			t.Error("503 response missing Retry-After")
		}
		// 503 body is RFC 7807 problem+json, not COSE.
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
			t.Errorf("503 content-type: got %q want JSON", ct)
		}
	}
	if rec.Code == http.StatusOK {
		// 200 body is raw COSE_Sign1 CBOR — explicitly NOT JSON.
		if ct := rec.Header().Get("Content-Type"); ct != receiptpkg.MediaType {
			t.Errorf("200 content-type: got %q want %q", ct, receiptpkg.MediaType)
		}
		if rec.Body.Len() == 0 {
			t.Error("200 response body is empty")
		}
		// Body must round-trip through the offline verifier against
		// the receipt PEM we exposed on /root-keys. That
		// closes the loop — the handler emits bytes we can actually
		// verify with only the public info a third party has.
		if err := receiptpkg.VerifyWithPEM(rec.Body.Bytes(), string(tb.signPubPEM)); err != nil {
			t.Errorf("offline verify: %v", err)
		}
	}
}

// TestGetStatusToken_ActiveAgent drives the happy path: append an
// event, then request a status token, and confirm the binary CBOR
// comes back under the expected content type. The token's content
// is verified separately in the receipt package's unit tests; here
// we're asserting the HTTP plumbing.
func TestGetStatusToken_ActiveAgent(t *testing.T) {
	tb := newTLTestbed(t)
	body := []byte(mustJSON(t, tb.inner))
	if rec := tb.postEvent(t, body, tb.signWithProducer(t, body)); rec.Code != http.StatusOK {
		t.Fatalf("seed event: got %d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/v1/agents/"+tb.inner.AnsID+"/status-token", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != receiptpkg.StatusTokenMediaType {
		t.Errorf("content-type: got %q want %q", ct, receiptpkg.StatusTokenMediaType)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("empty body")
	}
	if rec.Body.Bytes()[0] != 0xd2 {
		t.Errorf("first byte: got 0x%02x want 0xd2 (COSE_Sign1 tag 18)", rec.Body.Bytes()[0])
	}
}

// TestGetStatusToken_NoEvents confirms 404 when the agent has no
// events at all in the log — distinct from 410 (terminal state).
func TestGetStatusToken_NoEvents(t *testing.T) {
	tb := newTLTestbed(t)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/agents/00000000-0000-4000-8000-000000000999/status-token", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404; body=%s", rec.Code, rec.Body)
	}
}

// TestGetStatusToken_TerminalAgent asserts that once an agent has
// been revoked (terminal state), the endpoint returns 410 Gone and
// the `AGENT_TERMINAL` problem code — mirroring reference §297.
func TestGetStatusToken_TerminalAgent(t *testing.T) {
	tb := newTLTestbed(t)

	// Seed a registration event then a revocation event, both for
	// the same agent. Derived status lands on REVOKED (terminal).
	body := []byte(mustJSON(t, tb.inner))
	if rec := tb.postEvent(t, body, tb.signWithProducer(t, body)); rec.Code != http.StatusOK {
		t.Fatalf("seed register: %d", rec.Code)
	}
	revoke := tb.inner
	revoke.EventType = event.TypeAgentRevoked
	revoke.Timestamp = "2026-04-19T00:00:00Z"
	revoke.IssuedAt = revoke.Timestamp
	revokeBody := []byte(mustJSON(t, revoke))
	if rec := tb.postEvent(t, revokeBody, tb.signWithProducer(t, revokeBody)); rec.Code != http.StatusOK {
		t.Fatalf("seed revoke: %d body=%s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/v1/agents/"+tb.inner.AnsID+"/status-token", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("status: got %d want 410; body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "AGENT_TERMINAL" {
		t.Errorf("code: got %q want AGENT_TERMINAL", prob.Code)
	}
}

// TestGetSchema checks the three served versions. V0 + V1 are
// structural mirrors of the reference TL's schema endpoints so
// historical verifiers can resolve their event schemas through our
// TL; the one ans-wide deviation in V1 is the bare-semver `version`
// pattern (`^\d+\.\d+\.\d+$`) per the "TXT-payload version format"
// entry in CLAUDE.md, which states the v-prefixed form only lives
// inside the ANS name's hostname label. V2 is our own extended
// shape served when this build emits envelopes.
func TestGetSchema(t *testing.T) {
	tb := newTLTestbed(t)
	cases := []struct {
		version   string
		wantTitle string
	}{
		{"V0", "ANS Transparency Log Entry V0"},
		{"V1", "ANS Transparency Log Entry V1"},
		{"V2", "ANS Transparency Log Entry V2"},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/log/schema/"+tc.version, nil)
			rec := httptest.NewRecorder()
			tb.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", rec.Code, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("content-type: got %q", ct)
			}
			var obj map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &obj); err != nil {
				t.Fatalf("schema not JSON: %v", err)
			}
			if title, _ := obj["title"].(string); title != tc.wantTitle {
				t.Errorf("title: got %q want %q", title, tc.wantTitle)
			}
		})
	}
}

func TestGetSchema_UnknownVersion_404(t *testing.T) {
	tb := newTLTestbed(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/log/schema/V99", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
}

func TestGetCheckpointHistory_EmptyLog(t *testing.T) {
	tb := newTLTestbed(t)
	// No events appended yet → tl_checkpoints is empty. History
	// should return 200 with an empty array, not 404 — the reference
	// swagger §403 explicitly says "200 with empty array if offset
	// is out of bounds".
	req := httptest.NewRequest(http.MethodGet, "/v1/log/checkpoint/history", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Checkpoints []any `json:"checkpoints"`
		Pagination  struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Pagination.Total != 0 {
		t.Errorf("total: got %d want 0", resp.Pagination.Total)
	}
	if len(resp.Checkpoints) != 0 {
		t.Errorf("checkpoints: got %d entries want 0", len(resp.Checkpoints))
	}
}

func TestGetCheckpointHistory_BadLimit_422(t *testing.T) {
	tb := newTLTestbed(t)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/log/checkpoint/history?limit=999", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rec.Code)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "INVALID_PARAMETERS" {
		t.Errorf("code: got %q want INVALID_PARAMETERS", prob.Code)
	}
}

// TestGetCheckpoint_ReferenceParity asserts the /v1/log/checkpoint
// response carries every field the reference TL's CheckpointResponse
// emits — `publicKeyPem` on the outer object, and on each signature:
// the JWS fields (`jwsHeader`/`jwsPayload`/`jwsSignature`/`timestamp`)
// for JWS entries, plus `valid: true` for both the sumdb-note and JWS
// signatures when the signer keys verify correctly.
func TestGetCheckpoint_ReferenceParity(t *testing.T) {
	tb := newTLTestbed(t)

	// Append an event so Tessera seals a checkpoint.
	body := []byte(mustJSON(t, tb.inner))
	jws := tb.signWithProducer(t, body)
	if rec := tb.postEvent(t, body, jws); rec.Code != http.StatusOK {
		t.Fatalf("append: %d body=%s", rec.Code, rec.Body)
	}

	// Give Tessera a moment to land the checkpoint file. The default
	// checkpoint interval on the testbed is 100 ms.
	var rec *httptest.ResponseRecorder
	for range 50 {
		rec = httptest.NewRecorder()
		tb.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/log/checkpoint", nil))
		if rec.Code == http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("checkpoint: got %d body=%s", rec.Code, rec.Body)
	}

	var resp struct {
		LogSize          uint64 `json:"logSize"`
		RootHash         string `json:"rootHash"`
		OriginName       string `json:"originName"`
		CheckpointFormat string `json:"checkpointFormat"`
		CheckpointText   string `json:"checkpointText"`
		PublicKeyPem     string `json:"publicKeyPem"`
		Signatures       []struct {
			SignerName    string      `json:"signerName"`
			SignatureType string      `json:"signatureType"`
			Algorithm     string      `json:"algorithm"`
			KeyHash       string      `json:"keyHash"`
			RawSignature  string      `json:"rawSignature"`
			JwsHeader     interface{} `json:"jwsHeader"`
			JwsPayload    interface{} `json:"jwsPayload"`
			JwsSignature  string      `json:"jwsSignature"`
			Timestamp     string      `json:"timestamp"`
			Valid         bool        `json:"valid"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body)
	}
	// Production emits publicKeyPem as base64-encoded PEM; decode
	// and assert the underlying block shape.
	if resp.PublicKeyPem == "" {
		t.Fatal("publicKeyPem: want non-empty base64-encoded PEM")
	}
	pemBytes, perr := base64.StdEncoding.DecodeString(resp.PublicKeyPem)
	if perr != nil {
		t.Fatalf("publicKeyPem: base64 decode: %v", perr)
	}
	if !strings.Contains(string(pemBytes), "BEGIN PUBLIC KEY") {
		t.Errorf("publicKeyPem: want PEM block, decoded=%q", pemBytes)
	}

	// Assert the per-signature shape: two entries — one c2sp, one
	// jws — both verified, both carrying the same keyHash (since
	// the single TL signing key drives both lines).
	var sawC2SP, sawJWS bool
	var c2spKeyHash, jwsKeyHash string
	for _, s := range resp.Signatures {
		if !s.Valid {
			t.Errorf("signature %q (%s): valid=false — verifier should have confirmed at read time",
				s.SignerName, s.SignatureType)
		}
		if s.Algorithm != "ES256" {
			t.Errorf("signature %s: algorithm=%q, want ES256 (single-key topology)", s.SignatureType, s.Algorithm)
		}
		if !strings.HasPrefix(s.KeyHash, "0x") || len(s.KeyHash) != 10 {
			t.Errorf("signature %s: keyHash=%q, want 0x+8hex", s.SignatureType, s.KeyHash)
		}
		switch s.SignatureType {
		case "c2sp":
			sawC2SP = true
			c2spKeyHash = s.KeyHash
			if s.JwsHeader != nil || s.JwsPayload != nil || s.JwsSignature != "" || s.Timestamp != "" {
				t.Errorf("c2sp signature should not carry JWS fields: %+v", s)
			}
		case "jws":
			sawJWS = true
			jwsKeyHash = s.KeyHash
			if s.JwsSignature == "" {
				t.Error("jws signature: jwsSignature must be populated with the compact JWS")
			}
			if s.JwsHeader == nil {
				t.Error("jws signature: jwsHeader must decode to a non-nil object")
			}
			if s.JwsPayload == nil {
				t.Error("jws signature: jwsPayload must decode to a non-nil object")
			}
			if s.Timestamp == "" {
				t.Error("jws signature: timestamp must be populated from the `timestamp` claim")
			}
		default:
			t.Errorf("unknown signatureType %q (want c2sp or jws)", s.SignatureType)
		}
	}
	if !sawC2SP {
		t.Error("expected at least one c2sp signature")
	}
	if !sawJWS {
		t.Error("expected at least one jws signature")
	}
	if sawC2SP && sawJWS && c2spKeyHash != jwsKeyHash {
		t.Errorf("keyHash mismatch: c2sp=%s jws=%s — single-key topology should emit identical keyHash on both",
			c2spKeyHash, jwsKeyHash)
	}
}

func TestGetRootKeys(t *testing.T) {
	tb := newTLTestbed(t)
	req := httptest.NewRequest(http.MethodGet, "/root-keys", nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type: got %q want text/plain", ct)
	}
	body := rec.Body.String()
	// Body format matches production TL /root-keys: exactly one
	// `<origin>+<keyhash>+<base64(0x02 || SPKI)>` line — the single
	// TL signing key — terminated with \n.
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 1 {
		t.Fatalf("line count: got %d want 1; body=%q", len(lines), body)
	}
	parts := strings.SplitN(lines[0], "+", 3)
	if len(parts) != 3 {
		t.Fatalf("got %d parts want 3; line=%q", len(parts), lines[0])
	}
	if parts[0] != "ans-test" {
		t.Errorf("origin: got %q want ans-test", parts[0])
	}
	if len(parts[1]) != 8 {
		t.Errorf("keyhash length: got %d want 8", len(parts[1]))
	}
	if !strings.Contains(body, tb.signPubLine) {
		t.Error("signing verification line missing from root-keys body")
	}
}

// ----- testbed -----

type tlTestbed struct {
	router      chi.Router
	inner       event.Event
	producerKM  *signerKM
	pkStore     *producerkey.MemoryStore
	logSvc      *service.LogService
	eventStore  *sqlitetl.EventStore
	raID        string
	producerID  string
	signPubPEM  []byte // PEM for the single TL signing key (used for VerifyWithPEM)
	signPubLine string // sumdb-note verification line — matches /root-keys body
}

func newTLTestbed(t *testing.T) *tlTestbed {
	t.Helper()

	dir := t.TempDir()
	// 1. Single TL signing key — one ECDSA P-256 key drives every
	// outbound signature (primary C2SP, JWS additional signer, outer
	// envelope attestation, receipts, status tokens). Matches the
	// production TL's deployed topology.
	tlKM, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlKM.EnsureKey(context.Background(), "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	c2spSigner, err := logstore.NewC2SPECDSASigner(
		context.Background(), tlKM, "tl-sign", "ans-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	jwsSigner, err := logstore.NewJWSCheckpointSigner(
		context.Background(), tlKM, "tl-sign", "ans-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	jwsSigner.WithClock(func() int64 { return time.Now().Unix() })

	lg, err := logstore.Open(context.Background(), logstore.Config{
		DataDir:            filepath.Join(dir, "tiles"),
		Origin:             "ans-test",
		BatchSize:          1,
		BatchMaxAge:        50 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond,
	}, c2spSigner, logstore.WithAdditionalSigner(jwsSigner))
	if err != nil {
		t.Fatal(err)
	}
	// The lg-close + logSvc-close hook is installed after the
	// LogService is constructed below so test cleanup drains every
	// goroutine before tempdir cleanup runs.

	// 2. SQLite stores.
	db, err := sqlitetl.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	eventStore := sqlitetl.NewEventStore(db)
	cpStore := sqlitetl.NewCheckpointStore(db)
	receiptStore := sqlitetl.NewReceiptStore(db)

	// 3. Pubkey + /root-keys line — one key, one line.
	signPubAny, err := tlKM.GetPublicKey(context.Background(), "tl-sign")
	if err != nil {
		t.Fatal(err)
	}
	signPEM, err := keymanager.PublicKeyToPEM(signPubAny)
	if err != nil {
		t.Fatal(err)
	}
	signECDSA := signPubAny.(*ecdsa.PublicKey)
	signLine, err := anscrypto.PublicKeyToVerificationLine("ans-test", signECDSA)
	if err != nil {
		t.Fatal(err)
	}
	rootKeysBody := []byte(signLine + "\n")
	_ = signPEM // retained for the offline-verifier assertions below

	// 4. Producer key — register one that signs events.
	prodKM, prodPEM := newSignerKM(t, "prod-1")
	pkStore, err := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra-test-1", KeyID: "prod-1", Algorithm: "ES256", PublicKeyPEM: prodPEM},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Services.
	producerSig := service.NewProducerSigVerifier(pkStore)
	logSvc := service.NewLogService(
		lg, eventStore, cpStore,
		producerSig, tlKM, "tl-sign", "ans-test",
	)
	t.Cleanup(func() {
		// Drain LogService first so per-append awaiter goroutines
		// (which persist Tessera-signed checkpoints) settle before
		// Tessera's Close stops the underlying reader/appender.
		logSvc.Close()
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		_ = lg.Close(cctx)
	})
	badgeSvc := service.NewBadgeService(logSvc)
	identityBadgeSvc := service.NewIdentityBadgeService(logSvc, badgeSvc)
	receiptGen, err := receiptpkg.NewKeyManagerGenerator(
		context.Background(), tlKM, "tl-sign", "ans-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptSvc := service.NewReceiptService(logSvc, receiptStore, receiptGen)

	// Status-token generator reuses the same single key.
	statusGen, err := receiptpkg.NewKeyManagerStatusTokenGenerator(
		context.Background(), tlKM, "tl-sign", 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	statusSvc := service.NewStatusTokenService(logSvc, statusGen)

	signPEMBase64 := base64.StdEncoding.EncodeToString(signPEM)
	checkpointSvc := service.NewCheckpointService(cpStore).
		WithVerifiers(signECDSA, signPEMBase64)
	schemaSvc, err := service.NewSchemaService()
	if err != nil {
		t.Fatal(err)
	}

	// 6. Router.
	r := chi.NewRouter()
	h := handler.NewHandlers(
		logSvc, badgeSvc, identityBadgeSvc, receiptSvc, statusSvc,
		checkpointSvc, schemaSvc, rootKeysBody,
	)
	h.Mount(r, lg.DataDir())

	return &tlTestbed{
		router: r,
		inner: event.Event{
			AnsID:     "10000000-0000-4000-8000-000000000001",
			AnsName:   "ans://v1.0.0.agent.example.com",
			EventType: event.TypeAgentRegistered,
			Agent: &event.Agent{
				Host:    "agent.example.com",
				Name:    "test",
				Version: "1.0.0",
			},
			RaID:      "ra-test-1",
			IssuedAt:  "2026-04-17T00:00:00Z",
			Timestamp: "2026-04-17T00:00:00Z",
		},
		producerKM:  prodKM,
		pkStore:     pkStore,
		logSvc:      logSvc,
		eventStore:  eventStore,
		raID:        "ra-test-1",
		producerID:  "prod-1",
		signPubPEM:  signPEM,
		signPubLine: signLine,
	}
}

func (tb *tlTestbed) signWithProducer(t *testing.T, body []byte) string {
	t.Helper()
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), tb.producerKM, tb.producerID,
		anscrypto.JWSProtectedHeader{
			Typ:       "JWT",
			Timestamp: 1700000000,
			RAID:      tb.raID,
		},
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	return jws
}

// postEvent POSTs a V2-shape event body to the V2 ingest lane.
// The existing testbed builds V2 inner events (tb.inner is
// `event.Event`), so routes there. V1-shape tests use postEventV1.
func (tb *tlTestbed) postEvent(t *testing.T, body []byte, xsig string) *httptest.ResponseRecorder {
	t.Helper()
	return tb.postTo(t, "/v2/internal/agents/event", body, xsig)
}

// postEventV1 POSTs to the V1 ingest lane. V1-specific tests build a
// V1 envelope body and call this helper.
func (tb *tlTestbed) postEventV1(t *testing.T, body []byte, xsig string) *httptest.ResponseRecorder {
	t.Helper()
	return tb.postTo(t, "/v1/internal/agents/event", body, xsig)
}

// postTo is the shared ServeHTTP runner. Takes the full URL path so
// the caller picks its lane explicitly — keeps accidental cross-lane
// posts from ever slipping past the version guard silently.
func (tb *tlTestbed) postTo(t *testing.T, path string, body []byte, xsig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if xsig != "" {
		req.Header.Set("X-Signature", xsig)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	return rec
}

// ----- dual-lane ingest coverage -----

// v1Inner returns a V1-shape inner event mirroring the V2 fixture —
// same logical agent, different on-wire schema. Used by the V1
// ingest tests.
func (tb *tlTestbed) v1Inner() eventv1.Event {
	return eventv1.Event{
		AnsID:     tb.inner.AnsID,
		AnsName:   tb.inner.AnsName,
		EventType: eventv1.TypeAgentRegistered,
		Agent: &eventv1.Agent{
			Host:    tb.inner.Agent.Host,
			Name:    tb.inner.Agent.Name,
			Version: tb.inner.Agent.Version,
		},
		RaID:      tb.raID,
		IssuedAt:  tb.inner.IssuedAt,
		Timestamp: tb.inner.Timestamp,
	}
}

// TestAppendEventV1_HappyPath confirms the V1 ingest route accepts a
// well-formed V1 envelope and writes a V1 leaf to the log. The V1
// and V2 lanes are independent: a V1 leaf indexed at 0 here would
// coexist with V2 leaves under the same tree (different event_hash,
// different canonical bytes).
func TestAppendEventV1_HappyPath(t *testing.T) {
	tb := newTLTestbed(t)
	inner := tb.v1Inner()
	body := []byte(mustJSON(t, inner))
	jws := tb.signWithProducer(t, body)

	rec := tb.postEventV1(t, body, jws)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		LeafIndex uint64 `json:"leafIndex"`
		LeafHash  string `json:"leafHashHex"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.LeafHash) != 64 {
		t.Errorf("leaf hash should be 64 hex chars, got %d", len(resp.LeafHash))
	}
}

// TestAppendEvent_CrossSchemaRejection asserts both sides of the
// version guard: V1 envelopes posted to /v2 and V2 envelopes posted
// to /v1 are rejected when the attestation shape diverges.
//
// Background: the eventType enum is now shared (AGENT_REGISTERED,
// AGENT_RENEWED, AGENT_REVOKED, AGENT_DEPRECATED) so event-type
// alone no longer distinguishes the lanes — the envelope's
// attestation SHAPE is what differs (V1 singleton+rotation-array
// cert pairs + map-typed dnsRecordsProvisioned vs V2 unified
// identityCerts[]/serverCerts[] + typed dnsRecordsProvisioned[]
// arrays). Mismatched shapes hit a JSON unmarshal error, which the
// codec surfaces as INVALID_EVENT_BODY.
func TestAppendEvent_CrossSchemaRejection(t *testing.T) {
	tb := newTLTestbed(t)

	t.Run("V1 body on V2 route", func(t *testing.T) {
		inner := tb.v1Inner()
		// V1's dnsRecordsProvisioned is map[string]string. Give it a
		// value so the shape is concretely V1 and won't parse as the
		// V2 typed-array.
		if inner.Attestations == nil {
			inner.Attestations = &eventv1.Attestations{}
		}
		inner.Attestations.DNSRecordsProvisioned = map[string]string{
			"_ans.agent.example.com": "v=ans1; version=1.0.0; p=mcp",
		}
		body := []byte(mustJSON(t, inner))
		jws := tb.signWithProducer(t, body)
		rec := tb.postEvent(t, body, jws) // V2 route
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: got %d, want 422; body=%s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "INVALID_EVENT") {
			t.Errorf("expected INVALID_EVENT code, got %s", rec.Body.String())
		}
	})

	t.Run("V2 body on V1 route", func(t *testing.T) {
		// V2 inner with a typed dnsRecordsProvisioned[] array —
		// unmarshals as a slice on V2, fails on V1 (which declares
		// a map).
		inner := tb.inner
		inner.Attestations = &event.Attestations{
			DNSRecordsProvisioned: []event.DNSRecord{{
				Name: "_ans.agent.example.com",
				Type: "TXT",
				Data: "v=ans1; version=1.0.0; p=mcp",
			}},
		}
		body := []byte(mustJSON(t, inner))
		jws := tb.signWithProducer(t, body)
		rec := tb.postEventV1(t, body, jws) // V1 route
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: got %d, want 422; body=%s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "INVALID_EVENT") {
			t.Errorf("expected INVALID_EVENT code, got %s", rec.Body.String())
		}
	})
}

// TestAppendEventV1_StoresSchemaVersion pins the DB-level V1 parity:
// the `schema_version` column on the mirrored row records the schema
// the producer actually signed in. This is what the badge/audit
// read path echoes back in TransparencyLog.schemaVersion so clients
// pick the right parser.
func TestAppendEventV1_StoresSchemaVersion(t *testing.T) {
	tb := newTLTestbed(t)
	inner := tb.v1Inner()
	body := []byte(mustJSON(t, inner))
	jws := tb.signWithProducer(t, body)

	rec := tb.postEventV1(t, body, jws)
	if rec.Code != http.StatusOK {
		t.Fatalf("V1 append failed: %d %s", rec.Code, rec.Body)
	}
	stored, err := tb.eventStore.GetEventByLeafIndex(context.Background(), 0)
	if err != nil {
		t.Fatalf("get stored event: %v", err)
	}
	if stored.SchemaVersion != "V1" {
		t.Errorf("schema_version: got %q, want V1", stored.SchemaVersion)
	}
	// The raw envelope bytes should also stamp the V1 label at the
	// JSON level — this is what offline verifiers read.
	if !strings.Contains(stored.RawEvent, `"schemaVersion":"V1"`) {
		t.Errorf("stored envelope missing schemaVersion:V1; raw=%s", stored.RawEvent)
	}
}

// ----- helpers -----

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertStatusAndCode(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status: got %d, want %d; body=%s", rec.Code, wantStatus, rec.Body)
	}
	var prob struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("parse problem+json: %v body=%s", err, rec.Body)
	}
	if prob.Code != wantCode {
		t.Fatalf("code: got %q, want %q (detail=%s)", prob.Code, wantCode, prob.Detail)
	}
}

// ----- minimal Signer KeyManager used by the producer side of tests -----

type signerKM struct {
	id  string
	key *ecdsa.PrivateKey
}

func newSignerKM(t *testing.T, id string) (*signerKM, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.Public())
	return &signerKM{id: id, key: k}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (k *signerKM) Sign(_ context.Context, id string, data []byte) ([]byte, error) {
	if id != k.id {
		return nil, errors.New("no key")
	}
	return k.key.Sign(rand.Reader, data, crypto.SHA256)
}
func (k *signerKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) { return false, nil }
func (k *signerKM) GetPublicKey(_ context.Context, id string) (crypto.PublicKey, error) {
	if id != k.id {
		return nil, errors.New("no key")
	}
	return k.key.Public(), nil
}
func (k *signerKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (k *signerKM) ListKeys(_ context.Context) ([]string, error)          { return []string{k.id}, nil }

// silence unused imports that the testbed refactors in/out.
var (
	_ = io.EOF
	_ = strings.NewReader
	_ = hex.EncodeToString
)
