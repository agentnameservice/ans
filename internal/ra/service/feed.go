package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// The agent-events feed (GET /v1/agents/events). This file owns:
//
//   - the RA-side wire DTOs (EventPage / FeedEventItem / FeedEndpoint /
//     FeedFunction) — byte-compatible with the production swagger's
//     EventPageResponse / EventItem / AgentEndpoint / AgentFunction
//     (consumer mirror: internal/finder/feed);
//   - the domain→wire token map that bridges the OSS domain's
//     underscored protocol/transport constants (HTTP_API,
//     STREAMABLE_HTTP, JSON_RPC) to the production hyphenated wire
//     tokens (HTTP-API, STREAMABLE-HTTP, JSON-RPC);
//   - the projection from a delivered outbox row + registration +
//     endpoints into one wire EventItem.
//
// The feed serves only TL-acked rows (the store gates on
// sent_at_ms IS NOT NULL AND log_id IS NOT NULL), so "in the feed"
// implies "sealed in the log, receipt resolvable from logId".

// EventsFeedDefaultLimit is the page size used when the caller omits
// `limit`. Matches the production swagger default.
const EventsFeedDefaultLimit = 100

// EventsFeedMaxLimit is the largest page the feed will serve. Matches
// the production swagger maximum.
const EventsFeedMaxLimit = 200

// EventPage is one page of the agent-events feed. Byte-compatible with
// the swagger EventPageResponse: `items` is required and always
// marshals as an array (never null); `lastLogId` is the opaque
// next-page cursor, omitted at the tail.
type EventPage struct {
	Items     []FeedEventItem `json:"items"`
	LastLogID string          `json:"lastLogId,omitempty"`
}

// MarshalJSON guarantees `items` serializes as `[]` rather than `null`
// when the page is empty — the swagger marks items required.
func (p EventPage) MarshalJSON() ([]byte, error) {
	type alias EventPage
	a := alias(p)
	if a.Items == nil {
		a.Items = []FeedEventItem{}
	}
	return json.Marshal(a)
}

// FeedEventItem is one lifecycle event on the wire. Field names and
// optionality mirror the swagger EventItem field-for-field. providerId
// is intentionally never emitted by this RA (see buildFeedItem).
type FeedEventItem struct {
	LogID            string         `json:"logId"`
	EventType        string         `json:"eventType"`
	CreatedAt        string         `json:"createdAt"`
	ExpiresAt        string         `json:"expiresAt,omitempty"`
	AgentID          string         `json:"agentId"`
	AnsName          string         `json:"ansName"`
	AgentHost        string         `json:"agentHost"`
	AgentDisplayName string         `json:"agentDisplayName,omitempty"`
	AgentDescription string         `json:"agentDescription,omitempty"`
	Version          string         `json:"version"`
	ProviderID       string         `json:"providerId,omitempty"`
	Endpoints        []FeedEndpoint `json:"endpoints,omitempty"`
}

// FeedEndpoint mirrors the swagger AgentEndpoint. Note `metaDataUrl`
// (capital D) — the wire spelling differs from the domain's
// `metadataUrl`.
type FeedEndpoint struct {
	AgentURL         string         `json:"agentUrl"`
	MetaDataURL      string         `json:"metaDataUrl,omitempty"`
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	Protocol         string         `json:"protocol"`
	Functions        []FeedFunction `json:"functions,omitempty"`
	Transports       []string       `json:"transports,omitempty"`
}

// FeedFunction mirrors the swagger AgentFunction.
type FeedFunction struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// protocolToWire maps an OSS domain protocol token to its production
// wire token. Only HTTP_API differs (underscore → hyphen); A2A and MCP
// are identical across the two enums. An unrecognized token is
// returned unchanged so an enum the producer grows ahead of this map
// still reaches the consumer rather than being silently dropped — the
// conformance test pins the known set against the swagger enum.
func protocolToWire(p domain.Protocol) string {
	switch p {
	case domain.ProtocolHTTPAPI:
		return "HTTP-API"
	case domain.ProtocolA2A:
		return "A2A"
	case domain.ProtocolMCP:
		return "MCP"
	default:
		return string(p)
	}
}

// transportToWire maps an OSS domain transport token to its production
// wire token. Only STREAMABLE_HTTP and JSON_RPC differ (underscore →
// hyphen); SSE, GRPC, REST, HTTP are identical. Unrecognized tokens
// pass through unchanged (see protocolToWire rationale).
func transportToWire(t domain.Transport) string {
	switch t {
	case domain.TransportStreamableHTTP:
		return "STREAMABLE-HTTP"
	case domain.TransportJSONRPC:
		return "JSON-RPC"
	case domain.TransportSSE:
		return "SSE"
	case domain.TransportGRPC:
		return "GRPC"
	case domain.TransportREST:
		return "REST"
	case domain.TransportHTTP:
		return "HTTP"
	default:
		return string(t)
	}
}

// EventsService serves the agent-events feed. It reads delivered
// outbox rows through the port.FeedReader and projects each into a
// wire EventItem.
type EventsService struct {
	reader port.FeedReader
}

// NewEventsService constructs an EventsService.
func NewEventsService(reader port.FeedReader) *EventsService {
	return &EventsService{reader: reader}
}

// EventsInput is the validated, normalized query for ListEvents.
type EventsInput struct {
	// LastLogID is the caller's cursor. Empty starts from the oldest
	// retained row. An unknown or aged-out cursor also starts from the
	// oldest retained row (retention makes "expired" and "never
	// existed" indistinguishable).
	LastLogID string
	// Limit is the requested page size. Values <= 0 default to
	// EventsFeedDefaultLimit; values above EventsFeedMaxLimit are
	// clamped down.
	Limit int
	// ProviderID filters to a provider. The OSS RA has no provider
	// concept, so any non-empty value yields an empty page.
	ProviderID string
}

// ListEvents returns one page of the feed. The page's LastLogID is the
// logId of the last item, omitted when the page is empty.
func (s *EventsService) ListEvents(ctx context.Context, in EventsInput) (EventPage, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = EventsFeedDefaultLimit
	}
	if limit > EventsFeedMaxLimit {
		limit = EventsFeedMaxLimit
	}

	rows, err := s.reader.ReadFeed(ctx, port.FeedQuery{
		AfterLogID:     in.LastLogID,
		Limit:          limit,
		ProviderFilter: in.ProviderID,
	})
	if err != nil {
		return EventPage{}, fmt.Errorf("feed: read: %w", err)
	}

	items := make([]FeedEventItem, 0, len(rows))
	for i := range rows {
		item, buildErr := buildFeedItem(&rows[i])
		if buildErr != nil {
			return EventPage{}, fmt.Errorf("feed: project row logId=%q: %w", rows[i].LogID, buildErr)
		}
		items = append(items, item)
	}

	page := EventPage{Items: items}
	if len(items) > 0 {
		page.LastLogID = items[len(items)-1].LogID
	}
	return page, nil
}

// innerEvent is the minimal subset of the producer event (V1 or V2
// share these field names) the feed reads. The outbox payload's
// innerEventCanonical is JCS bytes of this shape; we parse it to lift
// the producer's authoritative createdAt/expiresAt and identity.
type innerEvent struct {
	AnsName   string `json:"ansName"`
	ExpiresAt string `json:"expiresAt"`
	Timestamp string `json:"timestamp"`
	Agent     *struct {
		Host    string `json:"host"`
		Version string `json:"version"`
	} `json:"agent"`
}

// buildFeedItem projects one store row into a wire EventItem.
//
// Field provenance:
//   - logId, eventType, agentId   ← the outbox row columns;
//   - createdAt                   ← the inner event `timestamp` (the
//     producer's authoritative RFC3339 time, NOT the row's wall-clock
//     created_at);
//   - expiresAt                   ← the inner event `expiresAt` when
//     present;
//   - ansName/agentHost/version   ← the inner event, falling back to
//     the registration row when the inner event omits them;
//   - agentDisplayName/Description ← the registration row;
//   - providerId                  ← OMITTED ALWAYS. The OSS RA's only
//     principal id is owner_id (the auth subject); emitting it would
//     leak the registrant's identity, and there is no provider concept
//     to populate it from;
//   - endpoints                   ← the agent_endpoints blob, mapped
//     to the wire shape (domain→wire token map + metadataUrl→metaDataUrl).
func buildFeedItem(row *port.FeedRow) (FeedEventItem, error) {
	var inner innerEvent
	if err := json.Unmarshal(row.PayloadJSON, &struct {
		InnerEventCanonical *innerEvent `json:"innerEventCanonical"`
	}{InnerEventCanonical: &inner}); err != nil {
		return FeedEventItem{}, fmt.Errorf("unmarshal outbox payload: %w", err)
	}

	ansName := firstNonEmpty(inner.AnsName, row.RegAnsName)
	version := row.RegVersion
	agentHost := row.RegAgentHost
	if inner.Agent != nil {
		agentHost = firstNonEmpty(inner.Agent.Host, agentHost)
		version = firstNonEmpty(inner.Agent.Version, version)
	}

	item := FeedEventItem{
		LogID:            row.LogID,
		EventType:        row.EventType,
		CreatedAt:        inner.Timestamp,
		ExpiresAt:        inner.ExpiresAt,
		AgentID:          row.AgentID,
		AnsName:          ansName,
		AgentHost:        agentHost,
		AgentDisplayName: row.RegDisplayName,
		AgentDescription: row.RegDescription,
		Version:          version,
		// ProviderID deliberately left zero — never emitted.
	}

	endpoints, err := feedEndpointsFromJSON(row.EndpointsJSON)
	if err != nil {
		return FeedEventItem{}, err
	}
	item.Endpoints = endpoints
	return item, nil
}

// feedEndpointsFromJSON decodes the stored domain endpoints blob and
// maps each to the wire shape. Returns nil (omitted on the wire) when
// the blob is empty or holds no endpoints.
func feedEndpointsFromJSON(raw []byte) ([]FeedEndpoint, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var domEndpoints []domain.AgentEndpoint
	if err := json.Unmarshal(raw, &domEndpoints); err != nil {
		return nil, fmt.Errorf("unmarshal endpoints: %w", err)
	}
	if len(domEndpoints) == 0 {
		return nil, nil
	}
	out := make([]FeedEndpoint, 0, len(domEndpoints))
	for _, ep := range domEndpoints {
		fe := FeedEndpoint{
			AgentURL:         ep.AgentURL,
			MetaDataURL:      ep.MetadataURL,
			DocumentationURL: ep.DocumentationURL,
			Protocol:         protocolToWire(ep.Protocol),
		}
		for _, fn := range ep.Functions {
			fe.Functions = append(fe.Functions, FeedFunction{
				ID:   fn.ID,
				Name: fn.Name,
				Tags: fn.Tags,
			})
		}
		for _, tr := range ep.Transports {
			fe.Transports = append(fe.Transports, transportToWire(tr))
		}
		out = append(out, fe)
	}
	return out, nil
}

// firstNonEmpty returns the first argument that is non-empty after
// trimming surrounding whitespace, or "" when all are blank.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
