package handler_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	anscrypto "github.com/godaddy/ans/internal/crypto"
)

// TestRegister_AgentCardContent_E2E_HashSealedAtActivation drives the
// full §A.1 flow and asserts the outbox-enqueued AGENT_REGISTERED
// event carries the expected hash:
//
//  1. POST /v2/ans/agents with agentCardContent → 202
//  2. POST /v2/ans/agents/{id}/verify-acme → 202 (PENDING_DNS)
//  3. POST /v2/ans/agents/{id}/verify-dns → 202 (ACTIVE)
//  4. Outbox.Claim → AGENT_REGISTERED row whose payload contains
//     attestations.metadataHashes.capabilitiesHash equal to
//     SHA-256(JCS(agentCardContent)).
//
// This is the closing assertion the AIM relies on: the badge response
// the TL eventually serves carries the same capabilitiesHash the
// operator's submitted Trust Card body produces under JCS+SHA-256.
func TestRegister_AgentCardContent_E2E_HashSealedAtActivation(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)

	cardBody := map[string]any{
		"ansName":          "ans://v1.0.0.e2ecard.example.com",
		"version":          "1.0.0",
		"agentDisplayName": "E2E Card",
		"endpoints": []map[string]any{
			{
				"protocol":    "MCP",
				"agentUrl":    "https://e2ecard.example.com/mcp",
				"transports":  []string{"SSE"},
				"metaDataUrl": "https://e2ecard.example.com/.well-known/agent-card.json",
			},
		},
	}
	cardJSON, err := json.Marshal(cardBody)
	if err != nil {
		t.Fatalf("marshal card body: %v", err)
	}

	// Compute the expected hash here so the assertion is independent
	// of the production code path. JCS canonicalization (RFC 8785) is
	// the same package the production hashAgentCardContent uses, but
	// invoking it in the test instead of importing the unexported
	// helper keeps the dependency boundary explicit.
	canonical, err := anscrypto.Canonicalize(cardJSON)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	digest := sha256.Sum256(canonical)
	wantHash := hex.EncodeToString(digest[:])

	registerBody, _ := json.Marshal(map[string]any{
		"agentDisplayName": "E2E",
		"version":          "1.0.0",
		"agentHost":        "e2ecard.example.com",
		"endpoints": []map[string]any{
			{"agentUrl": "https://e2ecard.example.com/mcp", "protocol": "MCP", "transports": []string{"SSE"}},
		},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.e2ecard.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "e2ecard.example.com"),
		"agentCardContent": cardBody,
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(registerBody), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: got %d body=%s", rec.Code, rec.Body)
	}
	var pending struct {
		AgentID string `json:"agentId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pending)
	if pending.AgentID == "" {
		t.Fatalf("agentId not populated in 202 body: %s", rec.Body)
	}
	agentID := pending.AgentID

	// Drive activation. The lifecycle helper goes through verify-acme
	// + verify-dns and produces the AGENT_REGISTERED outbox row.
	fx.activateAgent(t, "alice", agentID)

	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatalf("outbox claim: %v", err)
	}
	var registeredPayload []byte
	for _, row := range rows {
		if row.EventType == "AGENT_REGISTERED" {
			registeredPayload = row.PayloadJSON
			break
		}
	}
	if registeredPayload == nil {
		t.Fatalf("no AGENT_REGISTERED row found among %d outbox events", len(rows))
	}

	// The outbox payload is { innerEventCanonical, producerSignature }
	// — the inner event is the producer-signed payload that gets
	// posted to the TL. Walk innerEventCanonical.attestations.
	// metadataHashes.capabilitiesHash and confirm it matches.
	var envelope struct {
		InnerEventCanonical struct {
			Attestations struct {
				MetadataHashes map[string]string `json:"metadataHashes"`
			} `json:"attestations"`
		} `json:"innerEventCanonical"`
	}
	if err := json.Unmarshal(registeredPayload, &envelope); err != nil {
		t.Fatalf("decode envelope: %v\npayload=%s", err, registeredPayload)
	}
	gotHash := envelope.InnerEventCanonical.Attestations.MetadataHashes["capabilitiesHash"]
	if gotHash == "" {
		t.Fatalf("metadataHashes.capabilitiesHash missing from AGENT_REGISTERED payload\npayload=%s",
			registeredPayload)
	}
	if gotHash != wantHash {
		t.Errorf("metadataHashes.capabilitiesHash mismatch:\n  want %s\n  got  %s",
			wantHash, gotHash)
	}
}
