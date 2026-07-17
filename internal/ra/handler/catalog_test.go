package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// registerCatalogEligible registers an agent with an A2A endpoint that
// carries a same-host metaDataUrl, so it is catalog-eligible (versioned +
// A2A/MCP + policy-passing metaDataUrl). Returns the new agentId.
func (f *handlerFixture) registerCatalogEligible(t *testing.T, ownerID, host, version string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "Catalog Agent",
		"agentDescription": "An agent with a metadata URL.",
		"version":          version,
		"agentHost":        host,
		"endpoints": []map[string]any{
			{
				"agentUrl":    "https://" + host + "/a2a",
				"metaDataUrl": "https://" + host + "/.well-known/agent-card.json",
				"protocol":    "A2A",
				"transports":  []string{"JSON-RPC"},
				"functions": []map[string]any{
					{"id": "fn1", "name": "lookup", "tags": []string{"support"}},
				},
			},
		},
		"identityCsrPEM": newTestCSR(t, "ans://v"+version+"."+host),
		"serverCsrPEM":   newTestServerCSR(t, host),
	})
	rec := f.request(t, http.MethodPost, "/v2/ans/agents", bytes.NewReader(body), f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register %s: status=%d body=%s", host, rec.Code, rec.Body)
	}
	var resp struct {
		AgentID string `json:"agentId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AgentID == "" {
		t.Fatal("register returned empty agentId")
	}
	return resp.AgentID
}

// catalogDocResponse is a partial view of an AI Catalog document.
type catalogDocResponse struct {
	SpecVersion string `json:"specVersion"`
	Host        *struct {
		Identifier  string `json:"identifier"`
		DisplayName string `json:"displayName"`
	} `json:"host"`
	Entries []struct {
		Identifier string `json:"identifier"`
		MediaType  string `json:"mediaType"`
		Version    string `json:"version"`
	} `json:"entries"`
}

func TestHostCatalog_ActiveAgentAppears(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "ai-agent.acme.example.com"
	agentID := fx.registerCatalogEligible(t, "alice", host, "2.1.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/ai-catalog", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/ai-catalog+json" {
		t.Errorf("content-type = %q, want application/ai-catalog+json", ct)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("ETag must be set on a catalog document")
	}

	var doc catalogDocResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse document: %v", err)
	}
	if doc.SpecVersion != "1.0" {
		t.Errorf("specVersion = %q, want 1.0", doc.SpecVersion)
	}
	if doc.Host == nil || doc.Host.Identifier != host || doc.Host.DisplayName != host {
		t.Errorf("host object = %+v, want identifier=displayName=%q", doc.Host, host)
	}
	if len(doc.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (the ACTIVE agent)", len(doc.Entries))
	}
	if doc.Entries[0].Identifier != "urn:air:"+host+":agents:Catalog-Agent" {
		t.Errorf("entry identifier = %q", doc.Entries[0].Identifier)
	}
}

func TestHostCatalog_ETagThenNotModified(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "ai-agent.acme.example.com"
	agentID := fx.registerCatalogEligible(t, "alice", host, "2.1.0")
	fx.activateAgent(t, "alice", agentID)

	first := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/ai-catalog", nil, fx.asOwner("alice"))
	if first.Code != http.StatusOK {
		t.Fatalf("first GET status=%d", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first response")
	}

	// Conditional re-fetch with the ETag → 304, no body.
	second := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/ai-catalog", nil, func(r *http.Request) {
		fx.asOwner("alice")(r)
		r.Header.Set("If-None-Match", etag)
	})
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional GET status=%d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 must have no body, got %q", second.Body.String())
	}
	if second.Header().Get("ETag") != etag {
		t.Errorf("304 should echo the ETag")
	}
}

func TestHostCatalog_IfNoneMatchWildcardAndNonMatch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "ai-agent.acme.example.com"
	agentID := fx.registerCatalogEligible(t, "alice", host, "2.1.0")
	fx.activateAgent(t, "alice", agentID)
	path := "/v2/ans/agents/" + agentID + "/ai-catalog"

	// "*" matches any current representation → 304 (RFC 9110 §13.1.2).
	star := fx.request(t, http.MethodGet, path, nil, func(r *http.Request) {
		fx.asOwner("alice")(r)
		r.Header.Set("If-None-Match", "*")
	})
	if star.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: * status=%d, want 304", star.Code)
	}

	// A non-matching tag (among a list) → full 200 body.
	noMatch := fx.request(t, http.MethodGet, path, nil, func(r *http.Request) {
		fx.asOwner("alice")(r)
		r.Header.Set("If-None-Match", `"nope", W/"also-nope"`)
	})
	if noMatch.Code != http.StatusOK {
		t.Fatalf("non-matching If-None-Match status=%d, want 200", noMatch.Code)
	}
	if noMatch.Body.Len() == 0 {
		t.Error("non-matching conditional GET must return the full body")
	}
}

func TestHostCatalog_PendingAgentExcluded(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "pending-host.example.com"
	// Eligible but never activated → PENDING → excluded from the
	// well-known per-host document (§8). Document is still well-formed
	// with an empty entries array.
	agentID := fx.registerCatalogEligible(t, "alice", host, "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/ai-catalog", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var doc catalogDocResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc.Host == nil || doc.SpecVersion != "1.0" {
		t.Fatalf("document malformed: %s", rec.Body)
	}
	if len(doc.Entries) != 0 {
		t.Errorf("PENDING agent must not appear in the per-host doc; entries=%d", len(doc.Entries))
	}
}

// TestHostCatalog_HostComplete_MultipleVersions pins the core slice-2
// behavior: two ACTIVE catalog-eligible versions of the same owner's agent
// on one host BOTH appear in the per-host document.
func TestHostCatalog_HostComplete_MultipleVersions(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "multi-version.example.com"

	a1 := fx.registerCatalogEligible(t, "alice", host, "1.0.0")
	fx.activateAgent(t, "alice", a1)
	a2 := fx.registerCatalogEligible(t, "alice", host, "2.0.0")
	fx.activateAgent(t, "alice", a2)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+a1+"/ai-catalog", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var doc catalogDocResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (both ACTIVE versions on the host)", len(doc.Entries))
	}
	got := map[string]bool{doc.Entries[0].Version: true, doc.Entries[1].Version: true}
	if !got["1.0.0"] || !got["2.0.0"] {
		t.Errorf("want versions {1.0.0, 2.0.0}, got %v", got)
	}
	// Both versions share the one lineage handle: same display name →
	// same labelized URN segment (the Finder-parity derivation).
	wantURN := "urn:air:" + host + ":agents:Catalog-Agent"
	for _, e := range doc.Entries {
		if e.Identifier != wantURN {
			t.Errorf("entry identifier = %q, want %q", e.Identifier, wantURN)
		}
	}
}

func TestHostCatalog_NotOwnedReturns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerCatalogEligible(t, "alice", "ai-agent.acme.example.com", "2.1.0")
	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/ai-catalog", nil, fx.asOwner("bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-owner, got %d body=%s", rec.Code, rec.Body)
	}
}

// catalogEntryResponse is a partial view of the bare CatalogEntry used for
// assertions.
type catalogEntryResponse struct {
	Identifier  string   `json:"identifier"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	MediaType   string   `json:"mediaType"`
	URL         string   `json:"url"`
	Tags        []string `json:"tags"`
	Publisher   *struct {
		Identifier   string `json:"identifier"`
		DisplayName  string `json:"displayName"`
		IdentityType string `json:"identityType"`
	} `json:"publisher"`
	Metadata *struct {
		AnsName   string `json:"ansName"`
		AgentHost string `json:"agentHost"`
	} `json:"metadata"`
	TrustManifest *struct {
		Identity string `json:"identity"`
	} `json:"trustManifest"`
}

func TestCatalogEntry_EligibleReturns200(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerCatalogEligible(t, "alice", "ai-agent.acme.example.com", "2.1.0")
	// A catalog entry is published only once the agent is ACTIVE (sealed
	// in the TL), so drive it through activation first.
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/catalog-entry", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var entry catalogEntryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatalf("parse entry: %v", err)
	}
	if entry.Identifier != "urn:air:ai-agent.acme.example.com:agents:Catalog-Agent" {
		t.Errorf("identifier = %q", entry.Identifier)
	}
	if entry.MediaType != "application/a2a-agent-card+json" {
		t.Errorf("mediaType = %q", entry.MediaType)
	}
	if entry.URL != "https://ai-agent.acme.example.com/.well-known/agent-card.json" {
		t.Errorf("url = %q", entry.URL)
	}
	if entry.Version != "2.1.0" {
		t.Errorf("version = %q", entry.Version)
	}
	if entry.Publisher == nil || entry.Publisher.IdentityType != "dns" {
		t.Errorf("publisher = %+v", entry.Publisher)
	}
	if entry.Metadata == nil || entry.Metadata.AgentHost != "ai-agent.acme.example.com" {
		t.Errorf("metadata = %+v", entry.Metadata)
	}
	// Trust-manifest identity MUST equal the entry identifier (§5.1).
	if entry.TrustManifest == nil || entry.TrustManifest.Identity != entry.Identifier {
		t.Errorf("trustManifest identity must match identifier; got %+v", entry.TrustManifest)
	}
	if len(entry.Tags) != 1 || entry.Tags[0] != "support" {
		t.Errorf("tags = %v", entry.Tags)
	}
}

func TestCatalogEntry_IneligibleReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// ACTIVE agent whose only endpoint (MCP) has no metaDataUrl → eligible
	// on status but not on endpoint → 422 NOT_CATALOG_ELIGIBLE. Activated
	// so we exercise the endpoint gate, not the not-active gate.
	agentID := fx.registerAgent(t, "alice", "no-meta.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/catalog-entry", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("parse problem: %v", err)
	}
	if prob.Code != "NOT_CATALOG_ELIGIBLE" {
		t.Errorf("code = %q, want NOT_CATALOG_ELIGIBLE", prob.Code)
	}
	if prob.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", prob.Status)
	}
}

// TestCatalogEntry_NotActiveReturns422 is the core guard: a catalog entry
// is NOT available before the agent is set up. A registered-but-not-yet-
// ACTIVE agent (no TL entry, so nothing for the trust manifest/badge to
// link to) returns 422 rather than an entry pointing at a nonexistent
// receipt.
func TestCatalogEntry_NotActiveReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Eligible endpoint + version, but left PENDING (not activated).
	agentID := fx.registerCatalogEligible(t, "alice", "pending-agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/catalog-entry", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a pending agent must not have a catalog entry; status=%d body=%s, want 422", rec.Code, rec.Body)
	}
	var prob struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "NOT_CATALOG_ELIGIBLE" {
		t.Errorf("code = %q, want NOT_CATALOG_ELIGIBLE", prob.Code)
	}
}

func TestCatalogEntry_NotOwnedReturns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerCatalogEligible(t, "alice", "ai-agent.acme.example.com", "2.1.0")

	// Bob does not own Alice's agent → ReadOwnership 404s to hide
	// existence.
	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/catalog-entry", nil, fx.asOwner("bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-owner, got %d body=%s", rec.Code, rec.Body)
	}
}
