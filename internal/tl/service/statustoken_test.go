package service_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/godaddy/ans/internal/tl/event"
	receiptpkg "github.com/godaddy/ans/internal/tl/receipt"
	"github.com/godaddy/ans/internal/tl/service"
)

// TestStatusTokenService_ForAgent_WithAttestations drives the full
// status-token path on a stored event whose attestations carry both
// `identityCerts[]` and `metadataHashes` — covering
// extractCertFingerprints + extractMetadataHashes + the rest of
// buildStatusClaims. The token is verified offline as a smoke check
// that the resulting payload deserializes.
func TestStatusTokenService_ForAgent_WithAttestations(t *testing.T) {
	tb := newReceiptTestbed(t)

	// Replace the testbed's bare inner event with one that carries
	// rich attestations so buildStatusClaims has fields to extract.
	tb.inner.Attestations = &event.Attestations{
		IdentityCerts: []event.CertificateInfo{{
			Fingerprint: "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
			CertType:    "X509-OV-CLIENT",
			NotAfter:    "2027-04-17T00:00:00Z",
		}},
		ServerCerts: []event.CertificateInfo{{
			Fingerprint: "SHA256:1111111111111111111111111111111111111111111111111111111111111111",
			CertType:    "X509-DV-SERVER",
			NotAfter:    "2027-04-17T00:00:00Z",
		}},
		MetadataHashes: map[string]string{
			"MCP": "SHA256:abcd",
			"A2A": "SHA256:ef01",
		},
	}
	ansID := tb.appendEvent(t)
	tb.waitCheckpointCovers(t, ansID)

	// Build a StatusTokenService over the same logSvc + tlKM the
	// receipt testbed wired up. Use the receipt-key from the testbed
	// so the verifier check below has a matching public half.
	gen, err := receiptpkg.NewKeyManagerStatusTokenGenerator(
		context.Background(), tb.testKMHandle(), "tl-receipt", 0,
	)
	if err != nil {
		t.Fatalf("NewKeyManagerStatusTokenGenerator: %v", err)
	}
	statusSvc := service.NewStatusTokenService(tb.logSvc, gen)

	tok, err := statusSvc.ForAgent(context.Background(), ansID)
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	if len(tok.Bytes) == 0 {
		t.Fatal("status token bytes empty")
	}
	if tok.Bytes[0] != 0xd2 {
		t.Errorf("first byte: got 0x%02x want 0xd2 (COSE_Sign1 tag 18)", tok.Bytes[0])
	}

	// The token's payload should round-trip with the same key. We
	// don't parse it deeply here — just confirm the verifier accepts
	// it. The receipt testbed's receiptPub is the same key the
	// status-token generator was constructed against.
	payload, err := receiptpkg.VerifyStatusToken(tok.Bytes, tb.receiptPub)
	if err != nil {
		t.Fatalf("VerifyStatusToken: %v", err)
	}
	if payload.AgentID != ansID {
		t.Errorf("agentID: got %q want %q", payload.AgentID, ansID)
	}
	// The 2 cert fingerprints + 2 metadata hashes should ride through.
	if got := len(payload.ValidIdentityCerts); got != 1 {
		t.Errorf("ValidIdentityCerts: got %d want 1", got)
	}
	if got := len(payload.ValidServerCerts); got != 1 {
		t.Errorf("ValidServerCerts: got %d want 1", got)
	}
	if got := len(payload.MetadataHashes); got != 2 {
		t.Errorf("MetadataHashes: got %d want 2", got)
	}
}

// TestExtractor_HandlesEmptyAttestations covers the
// extractCertFingerprints / extractMetadataHashes paths where the
// inner event has an Attestations block but no cert / metadata
// entries. Drives buildStatusClaims's nil-fallback branches without
// needing a live log — we just append a minimal event and ask for
// a token.
func TestExtractor_HandlesEmptyAttestations(t *testing.T) {
	tb := newReceiptTestbed(t)

	// Empty Attestations object — this still serializes into the
	// envelope but each extract* call returns nil, exercising the
	// `len(out) == 0 → return nil` guard at the bottom of each
	// extractor.
	tb.inner.Attestations = &event.Attestations{}
	ansID := tb.appendEvent(t)
	tb.waitCheckpointCovers(t, ansID)

	gen, err := receiptpkg.NewKeyManagerStatusTokenGenerator(
		context.Background(), tb.testKMHandle(), "tl-receipt", 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	statusSvc := service.NewStatusTokenService(tb.logSvc, gen)

	tok, err := statusSvc.ForAgent(context.Background(), ansID)
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	payload, err := receiptpkg.VerifyStatusToken(tok.Bytes, tb.receiptPub)
	if err != nil {
		t.Fatalf("VerifyStatusToken: %v", err)
	}
	if len(payload.ValidIdentityCerts) != 0 || len(payload.ValidServerCerts) != 0 {
		t.Error("empty attestations should yield zero certs in token")
	}
	// Round-trip JSON the payload to make sure no extra fields
	// snuck in. The receipt-package struct lives behind a CBOR
	// codec on the wire so we don't gate JSON tags on it; this
	// test just exercises that Go's json package can serialize
	// it without panicking.
	if _, err := json.Marshal(payload); err != nil { //nolint:musttag // CBOR-tagged struct, JSON only used for the round-trip smoke check
		t.Errorf("json round-trip: %v", err)
	}
}
