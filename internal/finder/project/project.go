package project

import (
	"net/url"
	"sort"
	"strings"

	"github.com/godaddy/ans/internal/finder/feed"
)

// Media types the Finder emits per protocol (ARDS §3.3, §4.2). HTTP-API
// endpoints are not discoverable artifacts and produce no entry.
const (
	mediaTypeA2A = "application/a2a-agent-card+json"
	mediaTypeMCP = "application/mcp-server+json"
)

// well-known metadata filenames per discoverable protocol. Used to build
// the fallback artifact URL when an endpoint omits metaDataUrl.
const (
	wellKnownA2A = "/.well-known/agent-card.json"
	wellKnownMCP = "/.well-known/mcp.json"
)

// Attestation constants for the ANS-Registration trust claim.
const (
	attestationType      = "ANS-Registration"
	attestationMediaType = "application/scitt-receipt+cose"
)

// Caps on projected list fields (ARDS entries stay lean for fast
// filtering — capabilities and tags are discovery hints, not the full
// artifact).
const (
	maxCapabilities = 50
	maxTags         = 10
)

// Options configures projection. Both fields are injected (no globals,
// no clock): TLBaseURL is the base of the Transparency Log the
// ANS-Registration attestation URI is built against (empty omits the
// attestation), and AllowHTTP relaxes the emitted-URL scheme gate to
// permit http for local development.
type Options struct {
	TLBaseURL string
	AllowHTTP bool
}

// FromEvent projects one feed event into a Projection. It is the single
// exported entry point and the only place the lifecycle split is
// decided.
//
// Error vs Skip is pinned:
//
//   - A feed-contract violation (item.Validate fails) returns
//     (Projection{}, error). The caller must not advance its cursor past
//     a structurally invalid event without deciding what to do.
//   - An UNRECOGNIZED eventType returns a Projection carrying a single
//     alertable Skip{Kind: SkipUnknownEventType} and NO error. Returning
//     an error here would wedge ingestion at the cursor the moment the
//     producer's enum grows; a Skip lets the poll continue while still
//     surfacing the surprise.
//   - Record-level issues (a label that won't mint, an endpoint whose
//     URL fails policy, an unknown protocol token) become enumerated
//     Skips with the surviving entries still returned.
//
// The lifecycle split is the safety rule: REVOKED and DEPRECATED events
// mint an identity-only tombstone from required fields alone and never
// touch label minting or URL policy, so a malformed display field can
// never block a revocation from being recorded.
func FromEvent(item feed.EventItem, opts Options) (Projection, error) {
	if err := item.Validate(); err != nil {
		return Projection{}, err
	}

	switch item.EventType {
	case feed.EventTypeAgentRevoked:
		return tombstone(item, LifecycleRevoked), nil
	case feed.EventTypeAgentDeprecated:
		return tombstone(item, LifecycleDeprecated), nil
	case feed.EventTypeAgentRegistered, feed.EventTypeAgentRenewed:
		return projectActive(item, opts), nil
	default:
		return Projection{
			Entries: []ProjectedEntry{},
			Skipped: []Skip{{
				Kind:   SkipUnknownEventType,
				Detail: "unrecognized eventType " + quote(item.EventType),
			}},
		}, nil
	}
}

// tombstone mints the identity-only suppression record for a REVOKED or
// DEPRECATED event. It uses required identity fields only: AgentID,
// AnsName, LogID for the wrapper keys; timestamp = createdAt verbatim.
// The identifier is best-effort — included only when a label mints from
// the display name, never required (a display-less revocation still
// tombstones). No url/data, no display metadata, no trust manifest.
func tombstone(item feed.EventItem, lc Lifecycle) Projection {
	e := Entry{}
	// Best-effort identifier so the index can correlate the tombstone
	// with a prior Active entry by URN as well as by wrapper keys. A
	// missing label is fine here — the wrapper keys are authoritative.
	if urn, ok := mintURN(item.AgentHost, sanitizeText(item.AgentDisplayName)); ok {
		e.Identifier = urn
	}
	return Projection{
		Entries: []ProjectedEntry{{
			Entry:     e,
			Lifecycle: lc,
			AgentID:   item.AgentID,
			AnsName:   item.AnsName,
			LogID:     item.LogID,
			ExpiresAt: item.ExpiresAt,
		}},
	}
}

// projectActive fans an AGENT_REGISTERED/AGENT_RENEWED event out into one
// entry per includable endpoint. The URN label is minted once for the
// whole event; if it won't mint, the entire event Skips (one
// SkipMissingLabel) and no endpoints are projected.
func projectActive(item feed.EventItem, opts Options) Projection {
	displayName := sanitizeText(item.AgentDisplayName)

	urn, ok := mintURN(item.AgentHost, displayName)
	if !ok {
		return Projection{
			Entries: []ProjectedEntry{},
			Skipped: []Skip{{
				Kind:   SkipMissingLabel,
				Detail: "agentDisplayName produced no URN label for agent " + quote(item.AgentID),
			}},
		}
	}

	ctx := activeContext{
		item:        item,
		opts:        opts,
		urn:         urn,
		displayName: displayName,
		description: sanitizeText(item.AgentDescription),
		version:     sanitizeText(item.Version),
		trust:       buildTrustManifest(item, opts),
	}

	entries := make([]ProjectedEntry, 0, len(item.Endpoints))
	var skips []Skip

	for _, ep := range item.Endpoints {
		entry, skip := projectEndpoint(ctx, ep)
		if skip != nil {
			skips = append(skips, *skip)
			continue
		}
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	sortEntries(entries)

	return Projection{Entries: entries, Skipped: skips}
}

// activeContext bundles the per-event values computed once in
// projectActive and consumed by each endpoint projection: the sanitized
// display fields, the minted URN, and the shared trust manifest. It
// keeps projectEndpoint's signature small and pins the
// sanitize-once-per-event invariant (display name, description, and
// version are sanitized here, not per endpoint).
type activeContext struct {
	item        feed.EventItem
	opts        Options
	urn         string
	displayName string
	description string
	version     string
	trust       *TrustManifest
}

// projectEndpoint maps one endpoint to at most one entry. It returns
// (entry, nil) on success, (nil, skip) when the endpoint must be
// dropped, or (nil, nil) when the protocol is recognized but not
// discoverable (HTTP-API).
func projectEndpoint(ctx activeContext, ep feed.AgentEndpoint) (*ProjectedEntry, *Skip) {
	mediaType, wellKnown, ok := protocolArtifact(ep.Protocol)
	if !ok {
		// HTTP-API: recognized but not a discoverable artifact.
		if ep.Protocol == feed.ProtocolHTTPAPI {
			return nil, nil
		}
		return nil, &Skip{
			Kind:   SkipUnknownProtocol,
			Detail: "endpoint protocol " + quote(ep.Protocol) + " not recognized",
		}
	}

	artifactURL, skip := selectURL(ep, ctx.item.AgentHost, wellKnown, ctx.opts)
	if skip != nil {
		return nil, skip
	}

	entry := Entry{
		Identifier:    ctx.urn,
		DisplayName:   ctx.displayName,
		Type:          mediaType,
		URL:           artifactURL,
		Description:   ctx.description,
		Capabilities:  capabilitiesFrom(ep.Functions),
		Tags:          tagsFrom(ep.Functions),
		Version:       ctx.version,
		UpdatedAt:     ctx.item.CreatedAt,
		Metadata:      buildMetadata(ctx.item, ep, ctx.opts),
		TrustManifest: ctx.trust,
	}

	return &ProjectedEntry{
		Entry:     entry,
		Lifecycle: LifecycleActive,
		AgentID:   ctx.item.AgentID,
		AnsName:   ctx.item.AnsName,
		LogID:     ctx.item.LogID,
		ExpiresAt: ctx.item.ExpiresAt,
	}, nil
}

// protocolArtifact maps a wire protocol token to its emitted media type
// and well-known filename. The third result is false for HTTP-API
// (recognized, non-discoverable) and for any unrecognized token; the
// caller distinguishes the two.
func protocolArtifact(protocol string) (string, string, bool) {
	switch protocol {
	case feed.ProtocolA2A:
		return mediaTypeA2A, wellKnownA2A, true
	case feed.ProtocolMCP:
		return mediaTypeMCP, wellKnownMCP, true
	default:
		return "", "", false
	}
}

// selectURL picks the artifact URL for an endpoint and runs it through
// the single URL policy gate:
//
//   - metaDataUrl present  → validate it; on failure Skip FAIL-CLOSED
//     (no fallback rescue — a present-but-bad metaDataUrl is a publisher
//     error we refuse to paper over);
//   - metaDataUrl absent   → construct the well-known fallback and
//     validate THAT (the fallback is never trusted by construction).
//
// Either way the URL that reaches the entry has passed
// validateEmittedURL bound to the attested host.
func selectURL(
	ep feed.AgentEndpoint,
	attestedHost, wellKnown string,
	opts Options,
) (string, *Skip) {
	if strings.TrimSpace(ep.MetaDataURL) != "" {
		validated, err := validateEmittedURL(ep.MetaDataURL, attestedHost, opts.AllowHTTP)
		if err != nil {
			return "", &Skip{
				Kind:   SkipInvalidURL,
				Detail: "metaDataUrl failed policy: " + err.Error(),
			}
		}
		return validated, nil
	}

	fallback := "https://" + attestedHost + wellKnown
	validated, err := validateEmittedURL(fallback, attestedHost, opts.AllowHTTP)
	if err != nil {
		return "", &Skip{
			Kind:   SkipInvalidURL,
			Detail: "well-known fallback failed policy: " + err.Error(),
		}
	}
	return validated, nil
}

// buildMetadata assembles the entry's metadata map: ansName and logId
// always; agentUrl only when it passes URL policy (an invalid agentUrl
// is omitted, not a Skip — the entry survives on its metaDataUrl/
// fallback artifact URL). Every value passes the text chokepoint, since
// metadata string values are emitted content too; ansName and logId are
// already structurally validated by feed.Validate, so sanitizing them
// is defense-in-depth, and agentUrl already passed the stricter URL
// gate before it lands here.
func buildMetadata(item feed.EventItem, ep feed.AgentEndpoint, opts Options) map[string]string {
	md := map[string]string{
		"ansName": sanitizeText(item.AnsName),
		"logId":   sanitizeText(item.LogID),
	}
	if agentURL, err := validateEmittedURL(ep.AgentURL, item.AgentHost, opts.AllowHTTP); err == nil {
		md["agentUrl"] = agentURL
	}
	return md
}

// buildTrustManifest builds the trust manifest for an Active entry. The
// identity is the attested host as an https FQDN URI (host already
// validated). The ANS-Registration attestation is included only when a
// TLBaseURL is configured; an empty base URL omits attestations
// entirely (there is nowhere to point the receipt URI).
func buildTrustManifest(item feed.EventItem, opts Options) *TrustManifest {
	tm := &TrustManifest{
		Identity:     "https://" + item.AgentHost,
		IdentityType: "https",
	}
	if strings.TrimSpace(opts.TLBaseURL) != "" {
		receiptURI := strings.TrimRight(opts.TLBaseURL, "/") +
			"/v1/agents/" + url.PathEscape(item.AgentID) + "/receipt"
		tm.Attestations = []Attestation{{
			Type:      attestationType,
			URI:       receiptURI,
			MediaType: attestationMediaType,
		}}
	}
	return tm
}

// capabilitiesFrom projects function names into the capabilities list:
// sanitize each, drop empties, dedup, sort, cap at maxCapabilities.
func capabilitiesFrom(fns []feed.AgentFunction) []string {
	names := make([]string, 0, len(fns))
	for _, fn := range fns {
		names = append(names, fn.Name)
	}
	return dedupSortCap(names, maxCapabilities)
}

// tagsFrom projects the union of function tags: sanitize each, drop
// empties, dedup, sort, cap at maxTags.
func tagsFrom(fns []feed.AgentFunction) []string {
	tags := make([]string, 0, len(fns))
	for _, fn := range fns {
		tags = append(tags, fn.Tags...)
	}
	return dedupSortCap(tags, maxTags)
}

// dedupSortCap sanitizes each input string, drops any that sanitize to
// empty (BEFORE dedup, so a stripped-to-nothing value never occupies a
// slot), deduplicates, sorts, and caps the result length at limit.
// Returns nil when nothing survives so the field omits cleanly.
func dedupSortCap(in []string, limit int) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := sanitizeText(raw)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// sortEntries orders projected entries by (identifier, type, url). The
// tie-break on type then url matters because duplicate protocols on one
// agent are contract-legal: two MCP endpoints share identifier and type,
// so url is the final discriminator that keeps the order deterministic
// for golden tests.
func sortEntries(entries []ProjectedEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Identifier != b.Identifier {
			return a.Identifier < b.Identifier
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.URL < b.URL
	})
}

// quote wraps s in double quotes for human-readable Skip detail. Kept
// trivial and local so detail strings are consistent.
func quote(s string) string { return "\"" + s + "\"" }
