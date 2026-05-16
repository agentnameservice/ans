package handler

import (
	"errors"
	"testing"

	"github.com/godaddy/ans/internal/domain"
)

// TestResolveAnchorClaim_OmittedReturnsNil pins the legacy path:
// when the V2 register request has no anchor block, the handler
// returns a nil claim and the service falls back to FQDN-implicit
// behavior.
func TestResolveAnchorClaim_OmittedReturnsNil(t *testing.T) {
	claim, err := resolveAnchorClaim(nil, "agent.example.com")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if claim != nil {
		t.Errorf("expected nil claim, got %+v", claim)
	}
}

func TestResolveAnchorClaim_MissingType(t *testing.T) {
	_, err := resolveAnchorClaim(&anchorRequestDTO{Input: "agent.example.com"}, "agent.example.com")
	if err == nil {
		t.Fatal("expected INVALID_ANCHOR_TYPE, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "INVALID_ANCHOR_TYPE" {
		t.Errorf("expected INVALID_ANCHOR_TYPE, got %v", err)
	}
}

func TestResolveAnchorClaim_UnknownType(t *testing.T) {
	_, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "spiffe",
		Input:      "spiffe://example.org/foo",
	}, "agent.example.com")
	if err == nil {
		t.Fatal("expected INVALID_ANCHOR_TYPE, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "INVALID_ANCHOR_TYPE" {
		t.Errorf("expected INVALID_ANCHOR_TYPE, got %v", err)
	}
}

func TestResolveAnchorClaim_MissingInput(t *testing.T) {
	_, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "fqdn",
		Input:      "",
	}, "agent.example.com")
	if err == nil {
		t.Fatal("expected MISSING_ANCHOR_INPUT, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "MISSING_ANCHOR_INPUT" {
		t.Errorf("expected MISSING_ANCHOR_INPUT, got %v", err)
	}
}

func TestResolveAnchorClaim_FQDNAgentHostMustMatch(t *testing.T) {
	_, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "fqdn",
		Input:      "different.example.com",
	}, "agent.example.com")
	if err == nil {
		t.Fatal("expected ANCHOR_INPUT_AGENT_HOST_MISMATCH, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "ANCHOR_INPUT_AGENT_HOST_MISMATCH" {
		t.Errorf("expected ANCHOR_INPUT_AGENT_HOST_MISMATCH, got %v", err)
	}
}

func TestResolveAnchorClaim_FQDNCaseInsensitive(t *testing.T) {
	claim, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "fqdn",
		Input:      "AGENT.example.com",
	}, "agent.example.COM")
	if err != nil {
		t.Fatalf("expected case-insensitive match, got %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeFQDN {
		t.Errorf("AnchorType = %q", claim.AnchorType)
	}
}

func TestResolveAnchorClaim_DIDAcceptsArbitraryInput(t *testing.T) {
	claim, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "did",
		Input:      "did:web:agent.example.com",
	}, "agent.example.com")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeDID {
		t.Errorf("AnchorType = %q", claim.AnchorType)
	}
	if claim.ResolvedID != "did:web:agent.example.com" {
		t.Errorf("ResolvedID = %q", claim.ResolvedID)
	}
}

func TestResolveAnchorClaim_LEIAcceptsTwentyChar(t *testing.T) {
	claim, err := resolveAnchorClaim(&anchorRequestDTO{
		AnchorType: "lei",
		Input:      "529900T8BM49AURSDO55",
	}, "agent.example.com")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeLEI {
		t.Errorf("AnchorType = %q", claim.AnchorType)
	}
	if claim.ResolvedID != "529900T8BM49AURSDO55" {
		t.Errorf("ResolvedID = %q", claim.ResolvedID)
	}
}

func TestAnchorFields_NilOrEmptyClaim(t *testing.T) {
	at, ar := anchorFields(nil)
	if at != "" || ar != "" {
		t.Errorf("nil reg: anchor fields should be empty, got (%q, %q)", at, ar)
	}
	reg := &domain.AgentRegistration{}
	at, ar = anchorFields(reg)
	if at != "" || ar != "" {
		t.Errorf("empty claim: anchor fields should be empty, got (%q, %q)", at, ar)
	}
}

func TestAnchorFields_PopulatedClaim(t *testing.T) {
	reg := &domain.AgentRegistration{
		AnchorClaim: &domain.IdentityClaim{
			AnchorType: domain.AnchorTypeDID,
			ResolvedID: "did:web:agent.example.com",
		},
	}
	at, ar := anchorFields(reg)
	if at != "did" {
		t.Errorf("AnchorType = %q, want did", at)
	}
	if ar != "did:web:agent.example.com" {
		t.Errorf("AnchorResolvedID = %q", ar)
	}
}
