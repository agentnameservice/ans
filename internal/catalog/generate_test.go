package catalog

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

const (
	testHost    = "ai-agent.acmecorp.com"
	testAgentID = "550e8400-e29b-41d4-a716-446655440000"
	testTLBase  = "https://transparency-log.example.com"
)

var testUpdatedAt = time.Date(2026, 6, 12, 17, 3, 11, 0, time.UTC)

// newReg builds a versioned registration with the given endpoints. The
// host is the canonical test host; the version is 2.1.0.
func newReg(t *testing.T, endpoints ...domain.AgentEndpoint) *domain.AgentRegistration {
	t.Helper()
	return newRegHost(t, testHost, "2.1.0", endpoints...)
}

func newRegHost(t *testing.T, host, version string, endpoints ...domain.AgentEndpoint) *domain.AgentRegistration {
	t.Helper()
	sv, err := domain.ParseSemVer(version)
	if err != nil {
		t.Fatalf("ParseSemVer(%q): %v", version, err)
	}
	ans, err := domain.NewAnsName(sv, host)
	if err != nil {
		t.Fatalf("NewAnsName(%q,%q): %v", version, host, err)
	}
	return &domain.AgentRegistration{
		AgentID: testAgentID,
		AnsName: ans,
		// Catalog entries are produced only for ACTIVE agents (the TL
		// records the entry links to exist only after activation), so the
		// happy-path helper builds an ACTIVE registration. Tests that
		// exercise the not-active gate override Status explicitly.
		Status: domain.StatusActive,
		Details: domain.RegistrationDetails{
			DisplayName:           "Acme Support Agent",
			Description:           "Customer-support agent for Acme retail accounts.",
			RegistrationTimestamp: testUpdatedAt,
		},
		Endpoints: endpoints,
	}
}

func a2aEndpoint() domain.AgentEndpoint {
	return domain.AgentEndpoint{
		Protocol:    domain.ProtocolA2A,
		AgentURL:    "https://" + testHost + "/a2a",
		MetadataURL: "https://" + testHost + "/.well-known/agent-card.json",
	}
}

func mcpEndpoint() domain.AgentEndpoint {
	return domain.AgentEndpoint{
		Protocol:    domain.ProtocolMCP,
		AgentURL:    "https://" + testHost + "/mcp",
		MetadataURL: "https://" + testHost + "/.well-known/mcp/server-card.json",
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestBuildEntry_SingleA2A_Golden pins the full single-protocol entry
// shape, byte-for-byte, against the IMPL Appendix B.1 worked example —
// with the identifier label derived from the labelized display name
// ("Acme Support Agent" → "Acme-Support-Agent"), the same derivation the
// ARD Finder mints from feed events. Catches field-order and shape drift.
func TestBuildEntry_SingleA2A_Golden(t *testing.T) {
	reg := newReg(t, a2aEndpoint())

	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}

	const want = `{"identifier":"urn:air:ai-agent.acmecorp.com:agents:Acme-Support-Agent",` +
		`"displayName":"Acme Support Agent",` +
		`"description":"Customer-support agent for Acme retail accounts.",` +
		`"version":"2.1.0",` +
		`"mediaType":"application/a2a-agent-card+json",` +
		`"url":"https://ai-agent.acmecorp.com/.well-known/agent-card.json",` +
		`"updatedAt":"2026-06-12T17:03:11Z",` +
		`"publisher":{"identifier":"ai-agent.acmecorp.com","displayName":"ai-agent.acmecorp.com","identityType":"dns"},` +
		`"metadata":{"ansName":"ans://v2.1.0.ai-agent.acmecorp.com","agentHost":"ai-agent.acmecorp.com","badgeUrl":"https://transparency-log.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"},` +
		`"trustManifest":{"identity":"urn:air:ai-agent.acmecorp.com:agents:Acme-Support-Agent","attestations":[{"type":"ANS-Registration","uri":"https://transparency-log.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000/receipt","mediaType":"application/scitt-receipt+cose"}]}}`

	if got := mustJSON(t, entry); got != want {
		t.Errorf("entry JSON mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// TestBuildEntry_SingleMCP checks the MCP media type and that a single
// includable endpoint stays a plain top-level entry (no nesting).
func TestBuildEntry_SingleMCP(t *testing.T) {
	reg := newReg(t, mcpEndpoint())
	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.MediaType != mediaTypeMCP {
		t.Errorf("mediaType = %q, want %q", entry.MediaType, mediaTypeMCP)
	}
	if entry.Data != nil {
		t.Errorf("single endpoint must not nest; got Data = %+v", entry.Data)
	}
	if entry.URL != mcpEndpoint().MetadataURL {
		t.Errorf("url = %q, want %q", entry.URL, mcpEndpoint().MetadataURL)
	}
}

// TestBuildEntry_MultiProtocol_Nested pins the dual-protocol nested entry
// (§3.5): outer mediaType is the catalog type, Data holds one lean child
// per protocol, the trust manifest sits on the outer entry, and the outer
// entry carries no url.
func TestBuildEntry_MultiProtocol_Nested(t *testing.T) {
	reg := newReg(t, a2aEndpoint(), mcpEndpoint())
	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}

	if entry.MediaType != MediaTypeCatalog {
		t.Errorf("outer mediaType = %q, want %q", entry.MediaType, MediaTypeCatalog)
	}
	if entry.URL != "" {
		t.Errorf("outer entry must use data, not url; got url = %q", entry.URL)
	}
	if entry.Data == nil {
		t.Fatalf("outer entry must carry Data")
	}
	if entry.Data.SpecVersion != SpecVersion {
		t.Errorf("nested specVersion = %q, want %q", entry.Data.SpecVersion, SpecVersion)
	}
	if entry.TrustManifest == nil || entry.TrustManifest.Identity != entry.Identifier {
		t.Errorf("trust manifest must sit on outer entry with matching identity")
	}
	if len(entry.Data.Entries) != 2 {
		t.Fatalf("nested children = %d, want 2", len(entry.Data.Entries))
	}

	a2a := entry.Data.Entries[0]
	if a2a.Identifier != entry.Identifier+":a2a" {
		t.Errorf("a2a child identifier = %q", a2a.Identifier)
	}
	// Children reuse the parent's name verbatim — a protocol suffix could
	// push a maximum-length registered name past the published schema's
	// 64-char displayName cap, and the :a2a/:mcp identifier + mediaType
	// already discriminate the children.
	if a2a.DisplayName != "Acme Support Agent" {
		t.Errorf("a2a child displayName = %q", a2a.DisplayName)
	}
	if a2a.MediaType != mediaTypeA2A || a2a.URL != a2aEndpoint().MetadataURL {
		t.Errorf("a2a child media/url = %q/%q", a2a.MediaType, a2a.URL)
	}
	// Children stay lean: no trust manifest, metadata, or publisher.
	if a2a.TrustManifest != nil || a2a.Metadata != nil || a2a.Publisher != nil {
		t.Errorf("nested child must be lean, got %+v", a2a)
	}
	mcp := entry.Data.Entries[1]
	if mcp.Identifier != entry.Identifier+":mcp" || mcp.MediaType != mediaTypeMCP {
		t.Errorf("mcp child = %q/%q", mcp.Identifier, mcp.MediaType)
	}
}

// TestBuildEntry_Ineligible covers every §3.6 path that produces no entry.
func TestBuildEntry_Ineligible(t *testing.T) {
	httpAPI := domain.AgentEndpoint{
		Protocol:    domain.ProtocolHTTPAPI,
		AgentURL:    "https://" + testHost + "/api",
		MetadataURL: "https://" + testHost + "/openapi.json",
	}
	a2aNoMeta := domain.AgentEndpoint{
		Protocol: domain.ProtocolA2A,
		AgentURL: "https://" + testHost + "/a2a",
	}
	a2aCrossHost := domain.AgentEndpoint{
		Protocol:    domain.ProtocolA2A,
		AgentURL:    "https://" + testHost + "/a2a",
		MetadataURL: "https://evil.example.net/.well-known/agent-card.json",
	}

	tests := []struct {
		name       string
		endpoints  []domain.AgentEndpoint
		wantReason string
	}{
		{"http-api only", []domain.AgentEndpoint{httpAPI}, ReasonNoEligibleEndpoint},
		{"a2a without metaDataUrl", []domain.AgentEndpoint{a2aNoMeta}, ReasonNoEligibleEndpoint},
		{"a2a metaDataUrl fails policy", []domain.AgentEndpoint{a2aCrossHost}, ReasonNoEligibleEndpoint},
		{"no endpoints at all", nil, ReasonNoEligibleEndpoint},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := newReg(t, tc.endpoints...)
			_, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
			var ne *NotEligibleError
			if !errors.As(err, &ne) {
				t.Fatalf("want *NotEligibleError, got %v", err)
			}
			if ne.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", ne.Reason, tc.wantReason)
			}
			if ne.Error() == "" {
				t.Error("NotEligibleError message must be non-empty")
			}
		})
	}
}

// TestBuildEntry_MixedEndpoints_CollapsesToSingle verifies per-endpoint
// gating: ineligible endpoints are simply absent, and one surviving
// endpoint collapses back to the plain top-level form.
func TestBuildEntry_MixedEndpoints_CollapsesToSingle(t *testing.T) {
	httpAPI := domain.AgentEndpoint{
		Protocol:    domain.ProtocolHTTPAPI,
		AgentURL:    "https://" + testHost + "/api",
		MetadataURL: "https://" + testHost + "/openapi.json",
	}
	mcpNoMeta := domain.AgentEndpoint{
		Protocol: domain.ProtocolMCP,
		AgentURL: "https://" + testHost + "/mcp",
	}
	reg := newReg(t, httpAPI, a2aEndpoint(), mcpNoMeta)

	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.Data != nil {
		t.Errorf("only one endpoint is eligible; must not nest")
	}
	if entry.MediaType != mediaTypeA2A {
		t.Errorf("mediaType = %q, want a2a", entry.MediaType)
	}
}

// TestBuildEntry_NoTLBase omits the badge URL and the attestation when no
// TL base URL is configured, but still emits the manifest identity (§5.2).
func TestBuildEntry_NoTLBase(t *testing.T) {
	reg := newReg(t, a2aEndpoint())
	entry, err := BuildEntry(reg, Options{}) // no TL base
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.Metadata.BadgeURL != "" {
		t.Errorf("badgeUrl must be empty without TL base, got %q", entry.Metadata.BadgeURL)
	}
	if entry.TrustManifest == nil {
		t.Fatalf("trust manifest must still carry identity")
	}
	if entry.TrustManifest.Identity != entry.Identifier {
		t.Errorf("manifest identity must equal entry identifier")
	}
	if len(entry.TrustManifest.Attestations) != 0 {
		t.Errorf("attestations must be omitted without TL base, got %+v", entry.TrustManifest.Attestations)
	}
	// Confirm omitempty drops both from the wire.
	if js := mustJSON(t, entry); contains(js, "badgeUrl") || contains(js, "attestations") {
		t.Errorf("badgeUrl/attestations must not appear in JSON: %s", js)
	}
}

// TestBuildEntry_NilAndVersionless covers the Gate-1 and nil guards.
func TestBuildEntry_NilAndVersionless(t *testing.T) {
	t.Run("nil registration", func(t *testing.T) {
		_, err := BuildEntry(nil, Options{})
		var ne *NotEligibleError
		if !errors.As(err, &ne) || ne.Reason != ReasonNoVersion {
			t.Fatalf("want NO_VERSION NotEligibleError, got %v", err)
		}
	})
	t.Run("zero ansName", func(t *testing.T) {
		reg := &domain.AgentRegistration{AgentID: testAgentID, Endpoints: []domain.AgentEndpoint{a2aEndpoint()}}
		_, err := BuildEntry(reg, Options{})
		var ne *NotEligibleError
		if !errors.As(err, &ne) || ne.Reason != ReasonNoVersion {
			t.Fatalf("want NO_VERSION NotEligibleError, got %v", err)
		}
	})
}

// TestBuildEntry_Tags passes through and de-duplicates endpoint function
// tags onto a single-protocol entry.
func TestBuildEntry_Tags(t *testing.T) {
	ep := a2aEndpoint()
	ep.Functions = []domain.AgentFunction{
		{ID: "f1", Name: "lookup", Tags: []string{"billing", "support"}},
		{ID: "f2", Name: "refund", Tags: []string{"support", "payments"}},
	}
	reg := newReg(t, ep)
	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	want := []string{"billing", "support", "payments"}
	if mustJSON(t, entry.Tags) != mustJSON(t, want) {
		t.Errorf("tags = %v, want %v (deduped, first-seen order)", entry.Tags, want)
	}
}

// TestBuildEntry_SanitizesDisplayFields strips Cc/Cf runes from the
// emitted display fields.
func TestBuildEntry_SanitizesDisplayFields(t *testing.T) {
	reg := newReg(t, func() domain.AgentEndpoint {
		ep := a2aEndpoint()
		ep.Functions = []domain.AgentFunction{{ID: "f", Name: "n", Tags: []string{"safe\u202etag"}}}
		return ep
	}())
	reg.Details.DisplayName = "Acme\u202eSupport"             // bidi override
	reg.Details.Description = "desc\u200bwith\ufeffzerowidth" // zero-width + BOM

	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.DisplayName != "AcmeSupport" {
		t.Errorf("displayName not sanitized: %q", entry.DisplayName)
	}
	if entry.Description != "descwithzerowidth" {
		t.Errorf("description not sanitized: %q", entry.Description)
	}
	if len(entry.Tags) != 1 || entry.Tags[0] != "safetag" {
		t.Errorf("tag not sanitized: %v", entry.Tags)
	}
}

// TestBuildEntry_AllowInsecureURLs gates http metaDataUrl behind the dev
// override.
func TestBuildEntry_AllowInsecureURLs(t *testing.T) {
	ep := a2aEndpoint()
	ep.MetadataURL = "http://" + testHost + "/.well-known/agent-card.json"

	if _, err := BuildEntry(newReg(t, ep), Options{TLPublicBaseURL: testTLBase}); err == nil {
		t.Error("http metaDataUrl must be skipped without AllowInsecureURLs")
	}
	entry, err := BuildEntry(newReg(t, ep), Options{TLPublicBaseURL: testTLBase, AllowInsecureURLs: true})
	if err != nil {
		t.Fatalf("with AllowInsecureURLs: %v", err)
	}
	if entry.URL != ep.MetadataURL {
		t.Errorf("url = %q, want %q", entry.URL, ep.MetadataURL)
	}
}

// TestBuildEntry_ZeroTimestampOmitsUpdatedAt covers the rfc3339 zero
// branch.
func TestBuildEntry_ZeroTimestampOmitsUpdatedAt(t *testing.T) {
	reg := newReg(t, a2aEndpoint())
	reg.Details.RegistrationTimestamp = time.Time{}
	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.UpdatedAt != "" {
		t.Errorf("updatedAt must be empty for zero timestamp, got %q", entry.UpdatedAt)
	}
}

// TestBuildEntry_RenewalTimestampWins confirms updatedAt tracks the latest
// renewal when present.
func TestBuildEntry_RenewalTimestampWins(t *testing.T) {
	reg := newReg(t, a2aEndpoint())
	renewal := time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC)
	reg.Details.LastRenewalTimestamp = renewal
	entry, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	if entry.UpdatedAt != "2026-06-14T09:00:00Z" {
		t.Errorf("updatedAt = %q, want renewal time", entry.UpdatedAt)
	}
}

// TestBuildEntry_NotActive: a versioned, endpoint-eligible registration
// that is not ACTIVE produces no entry — its SCITT receipt and TL badge do
// not exist until the agent is sealed at activation.
func TestBuildEntry_NotActive(t *testing.T) {
	for _, st := range []domain.RegistrationStatus{
		domain.StatusPendingValidation,
		domain.StatusPendingDNS,
		domain.StatusFailed,
		domain.StatusRevoked,
		domain.StatusDeprecated,
	} {
		reg := newReg(t, a2aEndpoint())
		reg.Status = st
		_, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
		var ne *NotEligibleError
		if !errors.As(err, &ne) || ne.Reason != ReasonNotActive {
			t.Errorf("status %s: want AGENT_NOT_ACTIVE NotEligibleError, got %v", st, err)
		}
	}
}

// TestMintURN_SharedDerivation pins this package's URN seam to the shared
// internal/ard implementation the ARD Finder also projects through: one
// derivation, one lineage identifier per agent across both surfaces. The
// full label semantics are pinned in internal/ard's own tests; this seam
// test guards against the catalog ever reintroducing a local derivation.
func TestMintURN_SharedDerivation(t *testing.T) {
	got, ok := mintURN("AGENT.Example.com", "Acme  Support Agent")
	if !ok || got != "urn:air:agent.example.com:agents:Acme-Support-Agent" {
		t.Fatalf("mintURN = (%q, %v), want the shared ard derivation", got, ok)
	}
	if _, ok := mintURN("agent.example.com", "  "); ok {
		t.Fatal("whitespace-only display name must not mint a URN")
	}
}

// TestBuildEntry_NoLabel covers the mintable-label gate: a registration
// whose display name is empty (or sanitizes away to nothing) has no URN
// terminal segment, so no entry is produced — mirroring the ARD Finder,
// which skips such feed events rather than substituting a fallback.
func TestBuildEntry_NoLabel(t *testing.T) {
	reg := newReg(t, a2aEndpoint())
	reg.Details.DisplayName = "\u200b" // Cf-only: sanitizes to empty

	_, err := BuildEntry(reg, Options{TLPublicBaseURL: testTLBase})
	var ne *NotEligibleError
	if !errors.As(err, &ne) || ne.Reason != ReasonNoLabel {
		t.Fatalf("want NO_LABEL NotEligibleError, got %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
