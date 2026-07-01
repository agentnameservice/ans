package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/finder/feed"
	"github.com/godaddy/ans/internal/port"
	eventv1 "github.com/godaddy/ans/internal/tl/event/v1"
)

// fakeReader is a stub port.FeedReader for service-layer tests.
type fakeReader struct {
	rows  []port.FeedRow
	err   error
	lastQ port.FeedQuery
}

func (f *fakeReader) ReadFeed(_ context.Context, q port.FeedQuery) ([]port.FeedRow, error) {
	f.lastQ = q
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// canonicalV1 builds the outbox payload blob ({innerEventCanonical,
// producerSignature}) the store hands the service, with a producer
// event carrying the given timestamps + identity. Mirrors what the
// V1/V2 emit path persists.
func canonicalV1(t *testing.T, ansName, host, version, timestamp, expiresAt string) []byte {
	t.Helper()
	inner := map[string]any{
		"ansId":     "ignored-by-feed",
		"ansName":   ansName,
		"eventType": "AGENT_REGISTERED",
		"timestamp": timestamp,
		"agent": map[string]any{
			"host":    host,
			"version": version,
		},
	}
	if expiresAt != "" {
		inner["expiresAt"] = expiresAt
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(OutboxPayload{
		InnerEventCanonical: json.RawMessage(innerBytes),
		ProducerSignature:   "header..sig",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func endpointsJSON(t *testing.T, eps []domain.AgentEndpoint) []byte {
	t.Helper()
	b, err := json.Marshal(eps)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProtocolToWire(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   domain.Protocol
		want string
	}{
		{"http_api hyphenates", domain.ProtocolHTTPAPI, "HTTP-API"},
		{"a2a unchanged", domain.ProtocolA2A, "A2A"},
		{"mcp unchanged", domain.ProtocolMCP, "MCP"},
		{"unknown passes through", domain.Protocol("FUTURE_PROTO"), "FUTURE_PROTO"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := protocolToWire(tc.in); got != tc.want {
				t.Errorf("protocolToWire(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTransportToWire(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   domain.Transport
		want string
	}{
		{"streamable_http hyphenates", domain.TransportStreamableHTTP, "STREAMABLE-HTTP"},
		{"json_rpc hyphenates", domain.TransportJSONRPC, "JSON-RPC"},
		{"sse unchanged", domain.TransportSSE, "SSE"},
		{"grpc unchanged", domain.TransportGRPC, "GRPC"},
		{"rest unchanged", domain.TransportREST, "REST"},
		{"http unchanged", domain.TransportHTTP, "HTTP"},
		{"unknown passes through", domain.Transport("FUTURE_TRANSPORT"), "FUTURE_TRANSPORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := transportToWire(tc.in); got != tc.want {
				t.Errorf("transportToWire(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEventsService_ListEvents_LimitClamping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        int
		wantLimit int
	}{
		{"zero defaults", 0, EventsFeedDefaultLimit},
		{"negative defaults", -5, EventsFeedDefaultLimit},
		{"in range passes", 50, 50},
		{"over max clamps", 999, EventsFeedMaxLimit},
		{"at max passes", EventsFeedMaxLimit, EventsFeedMaxLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := &fakeReader{}
			svc := NewEventsService(reader)
			if _, err := svc.ListEvents(context.Background(), EventsInput{Limit: tc.in}); err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if reader.lastQ.Limit != tc.wantLimit {
				t.Errorf("clamped limit = %d, want %d", reader.lastQ.Limit, tc.wantLimit)
			}
		})
	}
}

func TestEventsService_ListEvents_EmptyPageMarshalsArray(t *testing.T) {
	t.Parallel()
	svc := NewEventsService(&fakeReader{rows: nil})
	page, err := svc.ListEvents(context.Background(), EventsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if page.LastLogID != "" {
		t.Errorf("empty page should omit lastLogId, got %q", page.LastLogID)
	}
	b, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"items":[]}` {
		t.Errorf("empty page JSON = %s, want {\"items\":[]}", b)
	}
}

func TestEventsService_ListEvents_LastLogIDFromTail(t *testing.T) {
	t.Parallel()
	reader := &fakeReader{rows: []port.FeedRow{
		{
			LogID:     "log-1",
			EventType: "AGENT_REGISTERED",
			AgentID:   "550e8400-e29b-41d4-a716-446655440000",
			PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
				"2025-01-08T12:30:00Z", ""),
		},
		{
			LogID:     "log-2",
			EventType: "AGENT_REVOKED",
			AgentID:   "550e8400-e29b-41d4-a716-446655440001",
			PayloadJSON: canonicalV1(t, "ans://v2.0.0.b.example.com", "b.example.com", "2.0.0",
				"2025-01-09T12:30:00Z", ""),
		},
	}}
	svc := NewEventsService(reader)
	page, err := svc.ListEvents(context.Background(), EventsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(page.Items))
	}
	if page.LastLogID != "log-2" {
		t.Errorf("lastLogId = %q, want log-2", page.LastLogID)
	}
}

func TestEventsService_ListEvents_PassesCursorAndProvider(t *testing.T) {
	t.Parallel()
	reader := &fakeReader{}
	svc := NewEventsService(reader)
	if _, err := svc.ListEvents(context.Background(), EventsInput{
		LastLogID:  "cursor-xyz",
		ProviderID: "PC_123",
	}); err != nil {
		t.Fatal(err)
	}
	if reader.lastQ.AfterLogID != "cursor-xyz" {
		t.Errorf("AfterLogID = %q, want cursor-xyz", reader.lastQ.AfterLogID)
	}
	if reader.lastQ.ProviderFilter != "PC_123" {
		t.Errorf("ProviderFilter = %q, want PC_123", reader.lastQ.ProviderFilter)
	}
}

func TestEventsService_ListEvents_ReaderError(t *testing.T) {
	t.Parallel()
	svc := NewEventsService(&fakeReader{err: errors.New("db down")})
	if _, err := svc.ListEvents(context.Background(), EventsInput{}); err == nil {
		t.Fatal("expected error from reader to propagate")
	}
}

func TestEventPage_MarshalJSON_PopulatedAndEmpty(t *testing.T) {
	t.Parallel()
	// Populated page: items array preserved, cursor present.
	pop := EventPage{
		Items:     []FeedEventItem{{LogID: "log-1", EventType: "AGENT_REGISTERED"}},
		LastLogID: "log-1",
	}
	b, err := json.Marshal(pop)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContains(b, `"logId":"log-1"`) || !bytesContains(b, `"lastLogId":"log-1"`) {
		t.Errorf("populated page JSON missing fields: %s", b)
	}
	// Empty page: nil items still marshals as [].
	empty := EventPage{}
	b, err = json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"items":[]}` {
		t.Errorf("empty page JSON = %s", b)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"first wins", []string{"a", "b"}, "a"},
		{"skips blank", []string{"  ", "b"}, "b"},
		{"all blank returns empty", []string{"", "   "}, ""},
		{"no args returns empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := firstNonEmpty(tc.in...); got != tc.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEventsService_ListEvents_MalformedPayloadErrors(t *testing.T) {
	t.Parallel()
	svc := NewEventsService(&fakeReader{rows: []port.FeedRow{
		{LogID: "log-1", AgentID: "550e8400-e29b-41d4-a716-446655440000", PayloadJSON: []byte("{not json")},
	}})
	if _, err := svc.ListEvents(context.Background(), EventsInput{}); err == nil {
		t.Fatal("expected error projecting malformed payload")
	}
}

func TestBuildFeedItem_NeverEmitsProviderID(t *testing.T) {
	t.Parallel()
	row := &port.FeedRow{
		LogID:     "log-1",
		EventType: "AGENT_REGISTERED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
			"2025-01-08T12:30:00Z", ""),
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	if item.ProviderID != "" {
		t.Errorf("providerId must never be emitted, got %q", item.ProviderID)
	}
	b, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContains(b, "providerId") {
		t.Errorf("marshaled item must omit providerId key entirely: %s", b)
	}
}

func TestBuildFeedItem_TimestampsFromInnerEvent(t *testing.T) {
	t.Parallel()
	row := &port.FeedRow{
		LogID:     "log-1",
		EventType: "AGENT_REGISTERED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
			"2025-01-08T12:30:00Z", "2026-01-08T12:30:00Z"),
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	if item.CreatedAt != "2025-01-08T12:30:00Z" {
		t.Errorf("createdAt = %q, want inner timestamp", item.CreatedAt)
	}
	if item.ExpiresAt != "2026-01-08T12:30:00Z" {
		t.Errorf("expiresAt = %q, want inner expiresAt", item.ExpiresAt)
	}
}

func TestBuildFeedItem_FallsBackToRegistrationIdentity(t *testing.T) {
	t.Parallel()
	// Inner event omits agent block and ansName; registration columns
	// supply the identity.
	inner, _ := json.Marshal(map[string]any{
		"ansId":     "x",
		"eventType": "AGENT_REGISTERED",
		"timestamp": "2025-01-08T12:30:00Z",
	})
	payload, _ := json.Marshal(OutboxPayload{
		InnerEventCanonical: json.RawMessage(inner),
		ProducerSignature:   "h..s",
	})
	row := &port.FeedRow{
		LogID:          "log-1",
		EventType:      "AGENT_REGISTERED",
		AgentID:        "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON:    payload,
		RegAnsName:     "ans://v3.0.0.fallback.example.com",
		RegAgentHost:   "fallback.example.com",
		RegVersion:     "3.0.0",
		RegDisplayName: "Fallback Agent",
		RegDescription: "from registration row",
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	if item.AnsName != "ans://v3.0.0.fallback.example.com" {
		t.Errorf("ansName fallback = %q", item.AnsName)
	}
	if item.AgentHost != "fallback.example.com" {
		t.Errorf("agentHost fallback = %q", item.AgentHost)
	}
	if item.Version != "3.0.0" {
		t.Errorf("version fallback = %q", item.Version)
	}
	if item.AgentDisplayName != "Fallback Agent" || item.AgentDescription != "from registration row" {
		t.Errorf("display metadata = %q / %q", item.AgentDisplayName, item.AgentDescription)
	}
}

func TestBuildFeedItem_MapsEndpointsToWireShape(t *testing.T) {
	t.Parallel()
	eps := []domain.AgentEndpoint{
		{
			Protocol:         domain.ProtocolHTTPAPI,
			AgentURL:         "https://a.example.com/api",
			MetadataURL:      "https://a.example.com/.well-known/api.json",
			DocumentationURL: "https://docs.a.example.com",
			Functions: []domain.AgentFunction{
				{ID: "get_thing", Name: "Get Thing", Tags: []string{"read"}},
			},
			Transports: []domain.Transport{domain.TransportStreamableHTTP, domain.TransportJSONRPC},
		},
	}
	row := &port.FeedRow{
		LogID:     "log-1",
		EventType: "AGENT_REGISTERED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
			"2025-01-08T12:30:00Z", ""),
		EndpointsJSON: endpointsJSON(t, eps),
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	if len(item.Endpoints) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(item.Endpoints))
	}
	ep := item.Endpoints[0]
	if ep.Protocol != "HTTP-API" {
		t.Errorf("protocol wire token = %q, want HTTP-API", ep.Protocol)
	}
	if ep.MetaDataURL != "https://a.example.com/.well-known/api.json" {
		t.Errorf("metaDataUrl = %q", ep.MetaDataURL)
	}
	wantTransports := []string{"STREAMABLE-HTTP", "JSON-RPC"}
	if len(ep.Transports) != 2 || ep.Transports[0] != wantTransports[0] || ep.Transports[1] != wantTransports[1] {
		t.Errorf("transports wire tokens = %v, want %v", ep.Transports, wantTransports)
	}
	// metaDataUrl (capital D) must be the marshaled key, not metadataUrl.
	b, _ := json.Marshal(ep)
	if !bytesContains(b, `"metaDataUrl"`) || bytesContains(b, `"metadataUrl"`) {
		t.Errorf("endpoint JSON must use metaDataUrl, not metadataUrl: %s", b)
	}
}

func TestBuildFeedItem_EmptyEndpointsOmitted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		blob []byte
	}{
		{"nil blob", nil},
		{"empty array", []byte("[]")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			row := &port.FeedRow{
				LogID:     "log-1",
				EventType: "AGENT_REGISTERED",
				AgentID:   "550e8400-e29b-41d4-a716-446655440000",
				PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
					"2025-01-08T12:30:00Z", ""),
				EndpointsJSON: tc.blob,
			}
			item, err := buildFeedItem(row)
			if err != nil {
				t.Fatal(err)
			}
			if item.Endpoints != nil {
				t.Errorf("expected nil endpoints, got %v", item.Endpoints)
			}
		})
	}
}

func TestBuildFeedItem_MalformedEndpointsErrors(t *testing.T) {
	t.Parallel()
	row := &port.FeedRow{
		LogID:     "log-1",
		EventType: "AGENT_REGISTERED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.a.example.com", "a.example.com", "1.0.0",
			"2025-01-08T12:30:00Z", ""),
		EndpointsJSON: []byte("{not an array"),
	}
	if _, err := buildFeedItem(row); err == nil {
		t.Fatal("expected error on malformed endpoints blob")
	}
}

// ─── Conformance tests (the plan's hard requirement) ───────────────

// swaggerProtocolEnum is the AgentEndpoint.protocol enum from the
// production swagger_ans.json `definitions.Protocol`, copied verbatim.
// Source: ~/Code/ans-registry-poc/swagger-docs/swagger_ans.json,
// definitions.Protocol.enum / definitions.AgentEndpoint.protocol.enum.
var swaggerProtocolEnum = map[string]bool{
	"A2A":      true,
	"MCP":      true,
	"HTTP-API": true,
}

// swaggerTransportEnum is the AgentEndpoint.transports[].enum from the
// production swagger_ans.json, copied verbatim.
// Source: definitions.AgentEndpoint.properties.transports.items.enum.
var swaggerTransportEnum = map[string]bool{
	"STREAMABLE-HTTP": true,
	"SSE":             true,
	"JSON-RPC":        true,
	"GRPC":            true,
	"REST":            true,
	"HTTP":            true,
}

// TestConformance_EnumValues asserts every wire token the domain→wire
// map can emit for a KNOWN domain constant is a member of the swagger
// enum set. This is enum-VALUE conformance, not just marshal shape.
//
// The domain sets are sourced from domain.AllProtocols()/AllTransports()
// — the canonical enumerations — rather than hand-copied here, so a new
// protocol/transport constant automatically enters this check and a
// missing wire mapping fails it.
func TestConformance_EnumValues(t *testing.T) {
	t.Parallel()

	for _, p := range domain.AllProtocols() {
		wire := protocolToWire(p)
		if !swaggerProtocolEnum[wire] {
			t.Errorf("protocol %q maps to wire %q which is NOT in the swagger Protocol enum", p, wire)
		}
	}

	for _, tr := range domain.AllTransports() {
		wire := transportToWire(tr)
		if !swaggerTransportEnum[wire] {
			t.Errorf("transport %q maps to wire %q which is NOT in the swagger transport enum", tr, wire)
		}
	}

	// The eventType tags the RA actually enqueues are the V1 producer
	// constants (the feed is a V1-lane route). Assert each is in the
	// swagger EventItem.eventType enum — hardcoded from
	// swagger_ans.json definitions.EventItem.properties.eventType.enum.
	swaggerEventTypes := map[string]bool{
		"AGENT_DEPRECATED": true, "AGENT_REGISTERED": true,
		"AGENT_REVOKED": true, "AGENT_RENEWED": true,
	}
	for _, et := range []eventv1.Type{
		eventv1.TypeAgentRegistered, eventv1.TypeAgentRevoked,
		eventv1.TypeAgentRenewed, eventv1.TypeAgentDeprecated,
	} {
		if !swaggerEventTypes[string(et)] {
			t.Errorf("enqueued event type %q is NOT in the swagger EventItem.eventType enum", et)
		}
		// The consumer mirror must expose the identical token string.
		if !feedExposesEventType(string(et)) {
			t.Errorf("event type %q has no matching feed.EventType* constant", et)
		}
	}
}

// feedExposesEventType reports whether the consumer mirror declares a
// constant with the given eventType value — guards producer/consumer
// token drift in both directions.
func feedExposesEventType(v string) bool {
	switch v {
	case feed.EventTypeAgentRegistered, feed.EventTypeAgentRevoked,
		feed.EventTypeAgentRenewed, feed.EventTypeAgentDeprecated:
		return true
	default:
		return false
	}
}

// representativeItem builds a fully-populated FeedEventItem exercising
// every field and the token map, for the byte-equality + Validate
// round-trips.
func representativeItem(t *testing.T) FeedEventItem {
	t.Helper()
	eps := []domain.AgentEndpoint{
		{
			Protocol:         domain.ProtocolHTTPAPI,
			AgentURL:         "https://sentiment.example.com/api",
			MetadataURL:      "https://sentiment.example.com/.well-known/api.json",
			DocumentationURL: "https://docs.sentiment.example.com",
			Functions: []domain.AgentFunction{
				{ID: "analyze", Name: "Analyze", Tags: []string{"nlp", "sentiment"}},
			},
			Transports: []domain.Transport{domain.TransportStreamableHTTP, domain.TransportJSONRPC},
		},
		{
			Protocol:   domain.ProtocolMCP,
			AgentURL:   "https://sentiment.example.com/mcp",
			Transports: []domain.Transport{domain.TransportSSE},
		},
	}
	row := &port.FeedRow{
		LogID:     "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
		EventType: "AGENT_REGISTERED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.sentiment.example.com", "sentiment.example.com", "1.0.0",
			"2025-01-08T12:30:00Z", "2026-01-08T12:30:00Z"),
		RegDisplayName: "Sentiment Analyzer",
		RegDescription: "An agent that analyzes sentiment in text",
		EndpointsJSON:  endpointsJSON(t, eps),
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

// minimalItem builds a FeedEventItem with only the swagger-required
// fields set — no expiresAt, displayName, description, or endpoints.
// This is the absence-direction conformance case: an omitempty tag that
// drifted between the RA DTO and the consumer mirror (one omits a zero
// field, the other emits `null`/`""`) only shows up when the field is
// actually absent.
func minimalItem(t *testing.T) FeedEventItem {
	t.Helper()
	row := &port.FeedRow{
		LogID:     "019a7a52-e5bf-7b5b-b048-d0b78f4b4c60",
		EventType: "AGENT_REVOKED",
		AgentID:   "550e8400-e29b-41d4-a716-446655440001",
		PayloadJSON: canonicalV1(t, "ans://v1.0.0.bare.example.com", "bare.example.com", "1.0.0",
			"2025-03-08T12:30:00Z", ""), // no expiresAt
		// no RegDisplayName / RegDescription / EndpointsJSON
	}
	item, err := buildFeedItem(row)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

// TestConformance_ByteEquality marshals the RA-side DTO, unmarshals
// through the consumer mirror (internal/finder/feed), re-marshals, and
// asserts byte-identity. A drift in any JSON tag or field presence
// breaks this. Run for both a fully-populated item and a minimal one so
// omitempty drift is caught in BOTH the presence and absence directions.
func TestConformance_ByteEquality(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		item FeedEventItem
	}{
		{"full item", representativeItem(t)},
		{"minimal item (only required fields)", minimalItem(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raBytes, err := json.Marshal(tc.item)
			if err != nil {
				t.Fatalf("marshal RA DTO: %v", err)
			}

			var mirror feed.EventItem
			if err := json.Unmarshal(raBytes, &mirror); err != nil {
				t.Fatalf("unmarshal through finder/feed mirror: %v", err)
			}
			mirrorBytes, err := json.Marshal(mirror)
			if err != nil {
				t.Fatalf("re-marshal mirror: %v", err)
			}
			if string(raBytes) != string(mirrorBytes) {
				t.Errorf("byte-equality FAILED\n RA-side: %s\n mirror : %s", raBytes, mirrorBytes)
			}

			// Page-level byte-equality too (items array + lastLogId cursor).
			page := EventPage{Items: []FeedEventItem{tc.item}, LastLogID: tc.item.LogID}
			pageBytes, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			var mirrorPage feed.EventPageResponse
			if err := json.Unmarshal(pageBytes, &mirrorPage); err != nil {
				t.Fatalf("unmarshal page through mirror: %v", err)
			}
			mirrorPageBytes, err := json.Marshal(mirrorPage)
			if err != nil {
				t.Fatal(err)
			}
			if string(pageBytes) != string(mirrorPageBytes) {
				t.Errorf("page byte-equality FAILED\n RA-side: %s\n mirror : %s", pageBytes, mirrorPageBytes)
			}
		})
	}
}

// TestConformance_ValidatePassesForEmittedItems round-trips every item
// the handler would emit through the consumer's feed.EventItem.Validate()
// gate — the contract every Finder consumer applies before projecting.
func TestConformance_ValidatePassesForEmittedItems(t *testing.T) {
	t.Parallel()
	reader := &fakeReader{rows: []port.FeedRow{
		{
			LogID:     "019a7a52-e5bf-7b5b-b048-d0b78f4b4c5f",
			EventType: "AGENT_REGISTERED",
			AgentID:   "550e8400-e29b-41d4-a716-446655440000",
			PayloadJSON: canonicalV1(t, "ans://v1.0.0.sentiment.example.com", "sentiment.example.com",
				"1.0.0", "2025-01-08T12:30:00Z", ""),
			RegDisplayName: "Sentiment Analyzer",
		},
		{
			LogID:     "019a7a52-e5bf-7b5b-b048-d0b78f4b4c60",
			EventType: "AGENT_REVOKED",
			AgentID:   "550e8400-e29b-41d4-a716-446655440001",
			PayloadJSON: canonicalV1(t, "ans://v2.1.0.revoked.example.com", "revoked.example.com",
				"2.1.0", "2025-02-08T12:30:00Z", ""),
		},
	}}
	svc := NewEventsService(reader)
	page, err := svc.ListEvents(context.Background(), EventsInput{})
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the page, decode through the mirror, validate each item.
	pageBytes, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	var mirror feed.EventPageResponse
	if err := json.Unmarshal(pageBytes, &mirror); err != nil {
		t.Fatal(err)
	}
	if len(mirror.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(mirror.Items))
	}
	for i, it := range mirror.Items {
		if err := it.Validate(); err != nil {
			t.Errorf("item %d failed feed.EventItem.Validate(): %v", i, err)
		}
	}
}

// bytesContains reports whether b contains sub.
func bytesContains(b []byte, sub string) bool {
	return bytes.Contains(b, []byte(sub))
}
