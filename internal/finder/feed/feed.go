// Package feed defines the consumer-side contract types for the ANS
// agent-events feed (`GET /v1/agents/events`). These types are the
// ingestion currency of the ANS Finder: the Finder polls the feed and
// projects each EventItem into a discovery catalog entry.
//
// The shapes here mirror the production ANS API swagger field-for-field
// — the canonical schema is developer.godaddy.com's `swagger_ans.json`.
// The OSS RA feed route owns a byte-equality and enum-value conformance
// test against that swagger; these consumer types are the other half of
// that contract, so JSON tags and field presence must not drift.
//
// Token values are the PRODUCTION HYPHENATED form (`HTTP-API`,
// `STREAMABLE-HTTP`, `JSON-RPC`), not the OSS domain's underscored
// constants (`HTTP_API`, `STREAMABLE_HTTP`, `JSON_RPC` in
// internal/domain/protocol.go). The feed is the wire; the domain is the
// internal representation. The OSS RA feed route owns the domain→wire
// token map that bridges them.
package feed

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

// EventPageResponse is one page of the agent-events feed.
//
// Mirrors swagger_ans.json `definitions.EventPageResponse`:
//   - `items` is required (the array is always present; it marshals as
//     `[]` rather than `null` when empty — see MarshalJSON below).
//   - `lastLogId` is the opaque cursor for the next page, omitted when
//     there are no more results.
type EventPageResponse struct {
	// Items is the page of events. Required by the swagger; never null
	// on the wire.
	Items []EventItem `json:"items"`
	// LastLogID is the cursor to pass as the next request's lastLogId.
	// Omitted when the page is the tail of the stream.
	LastLogID string `json:"lastLogId,omitempty"`
}

// MarshalJSON ensures Items always serializes as a JSON array, never
// `null`, matching the swagger's required-array contract. A nil slice
// would otherwise marshal as `null`.
func (r EventPageResponse) MarshalJSON() ([]byte, error) {
	type alias EventPageResponse // avoid recursion
	a := alias(r)
	if a.Items == nil {
		a.Items = []EventItem{}
	}
	return json.Marshal(a)
}

// EventItem is one ANS lifecycle event in the feed stream.
//
// Mirrors swagger_ans.json `definitions.EventItem`. Required fields per
// the swagger: logId, eventType, createdAt, agentId, ansName, agentHost,
// version. All display and endpoint fields are optional on the wire.
type EventItem struct {
	// LogID uniquely identifies this event in the stream.
	LogID string `json:"logId"`
	// EventType is one of the EventType* constants below.
	EventType string `json:"eventType"`
	// CreatedAt is an RFC 3339 timestamp of when the event was created.
	CreatedAt string `json:"createdAt"`
	// ExpiresAt is when the agent's registration expires (if
	// applicable). Optional.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// AgentID is the agent's UUID.
	AgentID string `json:"agentId"`
	// AnsName is the fully qualified ANS name: ans://{version}.{agentHost}.
	AnsName string `json:"ansName"`
	// AgentHost is the agent's hosting domain (FQDN).
	AgentHost string `json:"agentHost"`
	// AgentDisplayName is a human-readable display name. Optional.
	AgentDisplayName string `json:"agentDisplayName,omitempty"`
	// AgentDescription describes the agent. Optional.
	AgentDescription string `json:"agentDescription,omitempty"`
	// Version is the agent's semantic version.
	Version string `json:"version"`
	// ProviderID is the provider identifier associated with the agent,
	// if any. Optional.
	ProviderID string `json:"providerId,omitempty"`
	// Endpoints lists the agent's endpoints with protocol-specific
	// configuration. Optional.
	Endpoints []AgentEndpoint `json:"endpoints,omitempty"`
}

// AgentEndpoint is one protocol-specific endpoint of an agent.
//
// Mirrors swagger_ans.json `definitions.AgentEndpoint`. Required per the
// swagger: agentUrl, protocol. Protocol values are the production
// hyphenated tokens (ProtocolA2A, ProtocolMCP, ProtocolHTTPAPI).
type AgentEndpoint struct {
	// AgentURL is where the agent is hosted and accepts requests.
	AgentURL string `json:"agentUrl"`
	// MetaDataURL is the URL for agent metadata. Optional.
	MetaDataURL string `json:"metaDataUrl,omitempty"`
	// DocumentationURL is the URL for agent documentation. Optional.
	DocumentationURL string `json:"documentationUrl,omitempty"`
	// Protocol is the communication protocol for this endpoint
	// (ProtocolA2A | ProtocolMCP | ProtocolHTTPAPI).
	Protocol string `json:"protocol"`
	// Functions lists functions provided by this endpoint. The meaning
	// varies by protocol (MCP tools, A2A skills, HTTP-API routes).
	// Optional.
	Functions []AgentFunction `json:"functions,omitempty"`
	// Transports lists supported transport mechanisms (hyphenated
	// tokens, e.g. STREAMABLE-HTTP, JSON-RPC). Optional.
	Transports []string `json:"transports,omitempty"`
}

// AgentFunction describes a function an agent endpoint provides.
//
// Mirrors swagger_ans.json `definitions.AgentFunction`. Required per the
// swagger: id, name. tags is optional.
type AgentFunction struct {
	// ID uniquely identifies the function within the endpoint.
	ID string `json:"id"`
	// Name is a human-readable name for the function.
	Name string `json:"name"`
	// Tags categorize the function. Optional.
	Tags []string `json:"tags,omitempty"`
}

// Event type tokens. Values match swagger_ans.json
// `definitions.EventItem.eventType` enum.
const (
	EventTypeAgentRegistered = "AGENT_REGISTERED"
	EventTypeAgentRenewed    = "AGENT_RENEWED"
	EventTypeAgentRevoked    = "AGENT_REVOKED"
	EventTypeAgentDeprecated = "AGENT_DEPRECATED"
)

// Protocol tokens — the PRODUCTION HYPHENATED wire values from
// swagger_ans.json `definitions.Protocol`. Distinct from the OSS
// domain's underscored constants in internal/domain/protocol.go.
const (
	ProtocolA2A     = "A2A"
	ProtocolMCP     = "MCP"
	ProtocolHTTPAPI = "HTTP-API"
)

// Transport tokens — the PRODUCTION HYPHENATED wire values from
// swagger_ans.json `definitions.AgentEndpoint.transports`.
const (
	TransportStreamableHTTP = "STREAMABLE-HTTP"
	TransportSSE            = "SSE"
	TransportJSONRPC        = "JSON-RPC"
	TransportGRPC           = "GRPC"
	TransportREST           = "REST"
	TransportHTTP           = "HTTP"
)

// Validate enforces the EventItem's contract rules — the structural
// invariants the Finder relies on before projecting an event. Contract
// rules live with the contract type so every consumer of the feed gets
// the same gate. It checks the full contract:
//
//   - required-field presence (logId, eventType, createdAt, agentId,
//     ansName, agentHost, version);
//   - all the tombstone-key invariants below (ValidateIdentityKeys).
//
// Validate does NOT check eventType against the known enum — an
// unrecognized eventType is a projection-time concern (the producer's
// enum may grow), not a structural feed error.
//
// The lifecycle-aware caller runs ValidateIdentityKeys before deciding
// whether an event tombstones, and only runs this full Validate on the
// Active path. A field this method requires but ValidateIdentityKeys
// does not (eventType, agentHost, version) is therefore an Active-path
// requirement: a REVOKED/DEPRECATED event missing it still tombstones.
func (e EventItem) Validate() error {
	required := []struct {
		name  string
		value string
	}{
		{"eventType", e.EventType},
		{"agentHost", e.AgentHost},
		{"version", e.Version},
	}
	for _, f := range required {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("feed: EventItem missing required field %q", f.name)
		}
	}
	return e.ValidateIdentityKeys()
}

// ValidateIdentityKeys checks only the tombstone-key fields — the
// minimal set a tombstone is built from, and the only fields a
// REVOKED/DEPRECATED event needs to be structurally sound:
//
//   - logId is present;
//   - agentId is a UUID;
//   - createdAt is an RFC 3339 timestamp;
//   - ansName parses as an ANS name AND its FQDN equals the lowercased
//     agentHost (binds the host to the ansName in one step, which also
//     syntax-validates agentHost via domain.ParseAnsName's RFC 1123
//     hostname check, so a present-and-bound agentHost is implied here).
//
// It deliberately does NOT require eventType, agentHost-presence, or
// version: those are Active-path requirements (see Validate). Splitting
// the checks this way is the validation-layer half of the lifecycle
// safety rule — a revocation must not be dropped because of a field it
// never reads.
func (e EventItem) ValidateIdentityKeys() error {
	if strings.TrimSpace(e.LogID) == "" {
		return fmt.Errorf("feed: EventItem missing required field %q", "logId")
	}

	if !isUUID(e.AgentID) {
		return fmt.Errorf("feed: EventItem agentId %q is not a UUID", e.AgentID)
	}

	if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
		return fmt.Errorf("feed: EventItem createdAt %q is not RFC 3339: %w", e.CreatedAt, err)
	}

	parsed, err := domain.ParseAnsName(e.AnsName)
	if err != nil {
		return fmt.Errorf("feed: EventItem ansName %q is invalid: %w", e.AnsName, err)
	}
	if parsed.FQDN() != strings.ToLower(e.AgentHost) {
		return fmt.Errorf(
			"feed: EventItem agentHost %q does not match ansName FQDN %q",
			e.AgentHost, parsed.FQDN(),
		)
	}

	return nil
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex UUID.
func isUUID(s string) bool {
	const uuidLen = 36
	if len(s) != uuidLen {
		return false
	}
	for i, ch := range s {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !isHexDigit(ch) {
				return false
			}
		}
	}
	return true
}

// isHexDigit reports whether ch is a lowercase or uppercase hex digit.
func isHexDigit(ch rune) bool {
	return (ch >= '0' && ch <= '9') ||
		(ch >= 'a' && ch <= 'f') ||
		(ch >= 'A' && ch <= 'F')
}
