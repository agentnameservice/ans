package feed_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/finder/feed"
)

// validItem returns an EventItem that passes Validate. Tests mutate a
// copy to exercise each failure path.
func validItem() feed.EventItem {
	return feed.EventItem{
		LogID:            "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-01-08T12:30:00Z",
		ExpiresAt:        "2026-01-08T12:30:00Z",
		AgentID:          "550e8400-e29b-41d4-a716-446655440000",
		AnsName:          "ans://v1.0.0.myagent.example.com",
		AgentHost:        "myagent.example.com",
		AgentDisplayName: "Sentiment Analyzer",
		AgentDescription: "An agent that analyzes sentiment in text",
		Version:          "1.0.0",
		ProviderID:       "PC_1234567890",
		Endpoints: []feed.AgentEndpoint{
			{
				AgentURL:         "https://myagent.example.com/mcp",
				MetaDataURL:      "https://myagent.example.com/.well-known/mcp.json",
				DocumentationURL: "https://docs.myagent.example.com",
				Protocol:         feed.ProtocolMCP,
				Functions: []feed.AgentFunction{
					{ID: "domain_suggest", Name: "Domain Suggest", Tags: []string{"domain", "suggestion"}},
				},
				Transports: []string{feed.TransportStreamableHTTP},
			},
		},
	}
}

func TestEventItem_Validate_Success(t *testing.T) {
	t.Parallel()
	if err := validItem().Validate(); err != nil {
		t.Fatalf("Validate on valid item: %v", err)
	}
}

func TestEventItem_Validate_HostCaseInsensitive(t *testing.T) {
	t.Parallel()
	// agentHost differing only in case from the ansName FQDN must pass:
	// the bind compares against the lowercased host.
	it := validItem()
	it.AgentHost = "MyAgent.Example.COM"
	if err := it.Validate(); err != nil {
		t.Fatalf("Validate with mixed-case host: %v", err)
	}
}

func TestEventItem_Validate_Failures(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*feed.EventItem){
		"missing logId":        func(e *feed.EventItem) { e.LogID = "" },
		"blank logId":          func(e *feed.EventItem) { e.LogID = "   " },
		"missing eventType":    func(e *feed.EventItem) { e.EventType = "" },
		"missing createdAt":    func(e *feed.EventItem) { e.CreatedAt = "" },
		"missing agentId":      func(e *feed.EventItem) { e.AgentID = "" },
		"missing ansName":      func(e *feed.EventItem) { e.AnsName = "" },
		"missing agentHost":    func(e *feed.EventItem) { e.AgentHost = "" },
		"missing version":      func(e *feed.EventItem) { e.Version = "" },
		"agentId not uuid":     func(e *feed.EventItem) { e.AgentID = "not-a-uuid" },
		"agentId wrong length": func(e *feed.EventItem) { e.AgentID = "550e8400" },
		"agentId bad hex": func(e *feed.EventItem) {
			e.AgentID = "ZZZe8400-e29b-41d4-a716-446655440000"
		},
		"agentId bad dash": func(e *feed.EventItem) {
			e.AgentID = "550e8400xe29b-41d4-a716-446655440000"
		},
		"createdAt not rfc3339": func(e *feed.EventItem) { e.CreatedAt = "yesterday" },
		"ansName not parseable": func(e *feed.EventItem) { e.AnsName = "https://nope" },
		"agentHost mismatch": func(e *feed.EventItem) {
			e.AgentHost = "different.example.com"
		},
		// agentHost carrying path/@/: characters is rejected because the
		// ansName FQDN won't match it (and ParseAnsName validates the
		// host syntax in the ansName itself).
		"adversarial agentHost path": func(e *feed.EventItem) {
			e.AgentHost = "myagent.example.com/evil"
		},
		"adversarial agentHost userinfo": func(e *feed.EventItem) {
			e.AgentHost = "evil@myagent.example.com"
		},
		"adversarial agentHost port": func(e *feed.EventItem) {
			e.AgentHost = "myagent.example.com:8443"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			it := validItem()
			mutate(&it)
			if err := it.Validate(); err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
		})
	}
}

func TestEventItem_Validate_UUIDFormsAccepted(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"lowercase": "550e8400-e29b-41d4-a716-446655440000",
		"uppercase": "550E8400-E29B-41D4-A716-446655440000",
		"digits":    "00000000-0000-0000-0000-000000000000",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			it := validItem()
			it.AgentID = id
			if err := it.Validate(); err != nil {
				t.Fatalf("%s uuid %q rejected: %v", name, id, err)
			}
		})
	}
}

func TestEventItem_Validate_NonZOffsetCreatedAt(t *testing.T) {
	t.Parallel()
	it := validItem()
	it.CreatedAt = "2025-01-08T12:30:00-08:00"
	if err := it.Validate(); err != nil {
		t.Fatalf("non-Z RFC3339 offset rejected: %v", err)
	}
}

// TestEventPageResponse_Marshal_EmptyItemsIsArray pins the swagger
// contract that `items` is always a JSON array, never null.
func TestEventPageResponse_Marshal_EmptyItemsIsArray(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		resp     feed.EventPageResponse
		wantItem string
	}{
		"nil items": {
			resp:     feed.EventPageResponse{},
			wantItem: `"items":[]`,
		},
		"empty slice": {
			resp:     feed.EventPageResponse{Items: []feed.EventItem{}},
			wantItem: `"items":[]`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tc.resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(b), tc.wantItem) {
				t.Fatalf("got %s, want substring %s", b, tc.wantItem)
			}
			if strings.Contains(string(b), `"items":null`) {
				t.Fatalf("items marshaled as null: %s", b)
			}
		})
	}
}

func TestEventPageResponse_Marshal_PopulatedAndCursor(t *testing.T) {
	t.Parallel()
	resp := feed.EventPageResponse{
		Items:     []feed.EventItem{validItem()},
		LastLogID: "cursor-1",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"lastLogId":"cursor-1"`) {
		t.Fatalf("missing cursor: %s", s)
	}
	if !strings.Contains(s, `"logId":"019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f"`) {
		t.Fatalf("missing item logId: %s", s)
	}
}

func TestEventPageResponse_Marshal_OmitsEmptyCursor(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(feed.EventPageResponse{Items: []feed.EventItem{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "lastLogId") {
		t.Fatalf("empty cursor should be omitted: %s", b)
	}
}

// TestEventPageResponse_RoundTrip confirms unmarshal of a swagger-shaped
// page produces the expected typed values.
func TestEventPageResponse_RoundTrip(t *testing.T) {
	t.Parallel()
	const raw = `{
		"items": [
			{
				"logId": "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
				"eventType": "AGENT_REGISTERED",
				"createdAt": "2025-01-08T12:30:00Z",
				"expiresAt": "2026-01-08T12:30:00Z",
				"agentId": "550e8400-e29b-41d4-a716-446655440000",
				"ansName": "ans://v1.0.0.myagent.example.com",
				"agentHost": "myagent.example.com",
				"agentDisplayName": "Sentiment Analyzer",
				"agentDescription": "Analyzes sentiment",
				"version": "1.0.0",
				"providerId": "PC_1234567890",
				"endpoints": [
					{
						"agentUrl": "https://myagent.example.com/mcp",
						"metaDataUrl": "https://myagent.example.com/.well-known/mcp.json",
						"documentationUrl": "https://docs.myagent.example.com",
						"protocol": "MCP",
						"functions": [
							{"id": "domain_suggest", "name": "Domain Suggest", "tags": ["domain"]}
						],
						"transports": ["STREAMABLE-HTTP"]
					}
				]
			}
		],
		"lastLogId": "next-cursor"
	}`
	var resp feed.EventPageResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.LastLogID != "next-cursor" {
		t.Errorf("lastLogId: got %q", resp.LastLogID)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items: got %d, want 1", len(resp.Items))
	}
	it := resp.Items[0]
	if it.EventType != feed.EventTypeAgentRegistered {
		t.Errorf("eventType: got %q", it.EventType)
	}
	if it.AgentHost != "myagent.example.com" {
		t.Errorf("agentHost: got %q", it.AgentHost)
	}
	if len(it.Endpoints) != 1 || it.Endpoints[0].Protocol != feed.ProtocolMCP {
		t.Fatalf("endpoint protocol: got %+v", it.Endpoints)
	}
	if it.Endpoints[0].Transports[0] != feed.TransportStreamableHTTP {
		t.Errorf("transport: got %q", it.Endpoints[0].Transports[0])
	}
	if err := resp.Items[0].Validate(); err != nil {
		t.Errorf("round-tripped item fails Validate: %v", err)
	}
}

// TestTokenValues pins the production hyphenated token values. The OSS
// RA feed route's conformance test asserts these against the swagger;
// this guards against an accidental switch to the OSS domain's
// underscored forms.
func TestTokenValues(t *testing.T) {
	t.Parallel()
	pins := map[string]string{
		"EventTypeAgentRegistered": feed.EventTypeAgentRegistered,
		"EventTypeAgentRenewed":    feed.EventTypeAgentRenewed,
		"EventTypeAgentRevoked":    feed.EventTypeAgentRevoked,
		"EventTypeAgentDeprecated": feed.EventTypeAgentDeprecated,
		"ProtocolA2A":              feed.ProtocolA2A,
		"ProtocolMCP":              feed.ProtocolMCP,
		"ProtocolHTTPAPI":          feed.ProtocolHTTPAPI,
		"TransportStreamableHTTP":  feed.TransportStreamableHTTP,
		"TransportSSE":             feed.TransportSSE,
		"TransportJSONRPC":         feed.TransportJSONRPC,
		"TransportGRPC":            feed.TransportGRPC,
		"TransportREST":            feed.TransportREST,
		"TransportHTTP":            feed.TransportHTTP,
	}
	want := map[string]string{
		"EventTypeAgentRegistered": "AGENT_REGISTERED",
		"EventTypeAgentRenewed":    "AGENT_RENEWED",
		"EventTypeAgentRevoked":    "AGENT_REVOKED",
		"EventTypeAgentDeprecated": "AGENT_DEPRECATED",
		"ProtocolA2A":              "A2A",
		"ProtocolMCP":              "MCP",
		"ProtocolHTTPAPI":          "HTTP-API",
		"TransportStreamableHTTP":  "STREAMABLE-HTTP",
		"TransportSSE":             "SSE",
		"TransportJSONRPC":         "JSON-RPC",
		"TransportGRPC":            "GRPC",
		"TransportREST":            "REST",
		"TransportHTTP":            "HTTP",
	}
	for name, got := range pins {
		if got != want[name] {
			t.Errorf("%s: got %q, want %q", name, got, want[name])
		}
	}
}

// TestJSONTags pins the exact JSON tag names against the swagger. The
// OSS RA feed route's byte-equality test depends on these not drifting.
func TestJSONTags(t *testing.T) {
	t.Parallel()
	it := feed.EventItem{
		LogID:            "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
		EventType:        "AGENT_REGISTERED",
		CreatedAt:        "2025-01-08T12:30:00Z",
		ExpiresAt:        "2026-01-08T12:30:00Z",
		AgentID:          "550e8400-e29b-41d4-a716-446655440000",
		AnsName:          "ans://v1.0.0.x.example.com",
		AgentHost:        "x.example.com",
		AgentDisplayName: "X",
		AgentDescription: "desc",
		Version:          "1.0.0",
		ProviderID:       "PC_1",
		Endpoints: []feed.AgentEndpoint{{
			AgentURL:         "https://x.example.com/mcp",
			MetaDataURL:      "https://x.example.com/.well-known/mcp.json",
			DocumentationURL: "https://docs.x.example.com",
			Protocol:         "MCP",
			Functions:        []feed.AgentFunction{{ID: "i", Name: "n", Tags: []string{"t"}}},
			Transports:       []string{"STREAMABLE-HTTP"},
		}},
	}
	b, err := json.Marshal(it)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, tag := range []string{
		`"logId"`, `"eventType"`, `"createdAt"`, `"expiresAt"`, `"agentId"`,
		`"ansName"`, `"agentHost"`, `"agentDisplayName"`, `"agentDescription"`,
		`"version"`, `"providerId"`, `"endpoints"`,
		`"agentUrl"`, `"metaDataUrl"`, `"documentationUrl"`, `"protocol"`,
		`"functions"`, `"transports"`, `"id"`, `"name"`, `"tags"`,
	} {
		if !strings.Contains(s, tag) {
			t.Errorf("missing JSON tag %s in %s", tag, s)
		}
	}
}

// TestOmitempty confirms optional fields disappear when empty, so a
// minimal EventItem doesn't carry stray null/empty keys.
func TestOmitempty(t *testing.T) {
	t.Parallel()
	it := feed.EventItem{
		LogID:     "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
		EventType: "AGENT_REVOKED",
		CreatedAt: "2025-01-08T12:30:00Z",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		AnsName:   "ans://v1.0.0.x.example.com",
		AgentHost: "x.example.com",
		Version:   "1.0.0",
	}
	b, err := json.Marshal(it)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, absent := range []string{
		"expiresAt", "agentDisplayName", "agentDescription", "providerId", "endpoints",
	} {
		if strings.Contains(s, absent) {
			t.Errorf("optional field %q should be omitted: %s", absent, s)
		}
	}
}
