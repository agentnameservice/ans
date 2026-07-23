package catalog

import (
	"strings"
	"time"

	"github.com/agentnameservice/ans/internal/ard"
	"github.com/agentnameservice/ans/internal/domain"
)

// Options configures CatalogEntry generation.
type Options struct {
	// TLPublicBaseURL is the externally-reachable Transparency Log base
	// URL (e.g. "https://tl.example.org"). When empty — TL not
	// configured — the entry omits the badge URL and the trust
	// manifest's attestations rather than emit a malformed URI (§5.2);
	// the manifest still carries its identity. In production this is
	// required RA config, so attestations are always present.
	TLPublicBaseURL string
	// AllowInsecureURLs permits http metaDataUrl values to pass the URL
	// policy. A dev-only override (§3.8); false in production, where
	// only https is emitted.
	AllowInsecureURLs bool
}

// NotEligibleError reports that a registration produces no CatalogEntry
// (IMPL §3.6). The handler maps it to 422 NOT_CATALOG_ELIGIBLE; the
// registration response uses Reason as the machine-readable omission code.
type NotEligibleError struct {
	// Reason is a machine-readable code: ReasonNoVersion,
	// ReasonNotActive, or ReasonNoEligibleEndpoint.
	Reason string
	msg    string
}

// Machine-readable NotEligibleError reasons.
const (
	// ReasonNoVersion: the registration is versionless (§3.6 Gate 1).
	ReasonNoVersion = "NO_VERSION"
	// ReasonNotActive: the agent is not ACTIVE. A catalog entry carries an
	// ANS-Registration attestation (its SCITT receipt) and a TL badge URL,
	// and those Transparency-Log records only exist once the agent has been
	// sealed at activation. A pre-activation registration has no TL entry
	// to link to, so no catalog entry is produced until the agent is live.
	ReasonNotActive = "AGENT_NOT_ACTIVE"
	// ReasonNoEligibleEndpoint: no A2A/MCP endpoint carries a
	// policy-passing metaDataUrl (§3.6 Gate 2).
	ReasonNoEligibleEndpoint = "NO_ELIGIBLE_ENDPOINT"
	// ReasonNoLabel: the display name is missing or sanitizes away to
	// nothing, so no URN label can be minted. Mirrors the ARD Finder,
	// which skips such feed events instead of substituting a fallback
	// discovery handle.
	ReasonNoLabel = "NO_LABEL"
)

func (e *NotEligibleError) Error() string { return e.msg }

// BuildEntry serializes a registration aggregate into its CatalogEntry
// (IMPL §3). Every field is derived from the aggregate; nothing is fetched.
// It returns a *NotEligibleError when the registration produces no entry:
// versionless (§3.6 Gate 1), not ACTIVE (no Transparency-Log entry to link
// to yet), or no A2A/MCP endpoint with a policy-passing metaDataUrl (§3.6
// Gate 2). reg.Endpoints must be populated by the caller.
//
// The ACTIVE gate is load-bearing, not cosmetic: a catalog entry's trust
// manifest points at the agent's SCITT receipt and its metadata carries the
// TL badge URL, and both of those Transparency-Log records are created only
// when the agent is sealed at activation (verify-dns). Producing an entry
// for a pre-activation registration would advertise links to TL records
// that do not exist — so no entry is generated until the agent is live.
//
// Endpoint eligibility is evaluated per endpoint (§3.6 pseudocode): HTTP-API
// and unknown protocols produce no entry; an endpoint with no metaDataUrl
// produces no entry (no well-known fallback — ANS only points at metadata
// the registrant actually declared); a metaDataUrl that fails the URL
// policy (§3.8) is skipped. One eligible endpoint yields a plain top-level
// entry; two or more yield a nested outer entry (§3.5) whose Data holds a
// per-protocol child for each, so one agent can expose A2A and MCP without
// two top-level entries colliding on (identifier, version).
func BuildEntry(reg *domain.AgentRegistration, opts Options) (Entry, error) {
	if reg == nil {
		return Entry{}, &NotEligibleError{
			Reason: ReasonNoVersion,
			msg:    "registration is nil",
		}
	}

	// Gate 1: versioned only. Every catalog-eligible registration
	// carries a version (the ANSName is ans://{version}.{agentHost}),
	// which also keeps (identifier, version) unique by construction
	// (§3.4). Structurally always true in this RA — there is no
	// versionless registration path — but enforced honestly for spec
	// fidelity and any future base-only profile.
	if reg.AnsName.IsZero() || reg.AnsName.Version().IsZero() {
		return Entry{}, &NotEligibleError{
			Reason: ReasonNoVersion,
			msg:    "registration has no version; only versioned registrations are catalog-eligible",
		}
	}

	// Gate: the agent must be ACTIVE — sealed in the Transparency Log — so
	// the entry's SCITT-receipt attestation and badge URL reference TL
	// records that actually exist. A pending/failed registration has no TL
	// entry, so it is not catalogued until it goes live.
	if reg.Status != domain.StatusActive {
		return Entry{}, &NotEligibleError{
			Reason: ReasonNotActive,
			msg:    "agent is not ACTIVE; a catalog entry is published only after the agent is sealed in the Transparency Log",
		}
	}

	agentHost := reg.AnsName.AgentHost()

	// Gate: a mintable identifier. The URN derivation is shared with the
	// ARD Finder's search projection (internal/ard), so discovery and the
	// published catalog hand consumers ONE lineage identifier per agent.
	// A display name that is missing (it is optional at registration) or
	// sanitizes away to nothing yields no usable discovery handle; the
	// Finder skips such events, and the catalog mirrors that as
	// not-eligible rather than substituting a fallback segment.
	urn, ok := mintURN(agentHost, sanitizeText(reg.Details.DisplayName))
	if !ok {
		return Entry{}, &NotEligibleError{
			Reason: ReasonNoLabel,
			msg:    "registration has no display name to derive the URN label from; a catalog entry needs a usable lineage identifier",
		}
	}
	urn = sanitizeText(urn)

	// Gate 2: collect endpoints eligible for an entry.
	eligible := collectEligibleEndpoints(reg.Endpoints, agentHost, opts.AllowInsecureURLs)
	if len(eligible) == 0 {
		return Entry{}, &NotEligibleError{
			Reason: ReasonNoEligibleEndpoint,
			msg:    "registration has no A2A or MCP endpoint with a metadata URL eligible for cataloging",
		}
	}

	entry := Entry{
		Identifier:  urn,
		DisplayName: sanitizeText(reg.Details.DisplayName),
		Description: sanitizeText(reg.Details.Description),
		Version:     sanitizeText(reg.AnsName.Version().String()),
		// UpdatedAt: registration (or last-renewal) time is a deliberate
		// proxy for IMPL §3.1's "activation / latest seal timestamp" — the
		// RA persists no activation timestamp (Activate discards `now` into
		// the event only), and updatedAt is optional, so this is a fidelity
		// proxy, not the sealed go-live time.
		UpdatedAt:     rfc3339(reg.Details.EffectiveTimestamp()),
		Publisher:     buildPublisher(agentHost),
		Metadata:      buildMetadata(reg, opts.TLPublicBaseURL),
		TrustManifest: buildTrustManifest(urn, reg.AgentID, opts.TLPublicBaseURL),
	}

	if len(eligible) == 1 {
		// Single includable endpoint → plain top-level entry (§3.5).
		entry.MediaType = eligible[0].mediaType
		entry.URL = eligible[0].url
		entry.Tags = sanitizeTags(eligible[0].tags)
		return entry, nil
	}

	// Multiple includable endpoints → nested outer entry (§3.5). The
	// outer entry legally uses Data (an ANS-generated nested catalog,
	// not raw card bytes) and carries the trust manifest; children stay
	// lean.
	entry.MediaType = MediaTypeCatalog
	children := make([]Entry, 0, len(eligible))
	for _, e := range eligible {
		children = append(children, Entry{
			Identifier: urn + ":" + strings.ToLower(string(e.protocol)),
			// The child reuses the parent's name verbatim: it is already
			// fully discriminated by its :a2a/:mcp identifier segment and
			// its mediaType, and any suffix could push a maximum-length
			// (64-char) registered name past the published CatalogEntry
			// displayName cap — a 200 body that fails our own schema.
			DisplayName: sanitizeText(reg.Details.DisplayName),
			MediaType:   e.mediaType,
			URL:         e.url,
		})
	}
	entry.Data = &NestedCatalog{SpecVersion: SpecVersion, Entries: children}
	return entry, nil
}

// eligibleEndpoint is one endpoint that passed the §3.6 gate.
type eligibleEndpoint struct {
	protocol  domain.Protocol
	mediaType string
	url       string
	tags      []string
}

// collectEligibleEndpoints applies the §3.6 per-endpoint gate, preserving
// registration order: keep A2A/MCP endpoints whose metaDataUrl is present
// and passes the URL policy; skip everything else.
func collectEligibleEndpoints(endpoints []domain.AgentEndpoint, agentHost string, allowInsecure bool) []eligibleEndpoint {
	out := make([]eligibleEndpoint, 0, len(endpoints))
	for _, e := range endpoints {
		mt, ok := protocolMediaType(e.Protocol)
		if !ok {
			continue // HTTP-API / unknown → no entry
		}
		if e.MetadataURL == "" {
			continue // no declared metadata → no entry (no fallback)
		}
		safeURL, ok := validateEmittedURL(e.MetadataURL, agentHost, allowInsecure)
		if !ok {
			continue // fails URL policy → skip endpoint
		}
		out = append(out, eligibleEndpoint{
			protocol:  e.Protocol,
			mediaType: mt,
			url:       safeURL,
			tags:      collectTags(e.Functions),
		})
	}
	return out
}

// protocolMediaType maps a catalog-eligible protocol to its artifact media
// type. HTTP-API and any unknown protocol return false — they produce no
// catalog artifact type (§3.6). The protocol enum is A2A/MCP/HTTP-API;
// there is no PAYMENT.
func protocolMediaType(p domain.Protocol) (string, bool) {
	switch p {
	case domain.ProtocolA2A:
		return mediaTypeA2A, true
	case domain.ProtocolMCP:
		return mediaTypeMCP, true
	default:
		return "", false
	}
}

// mintURN is ard.MintURN — the single shared derivation of the
// urn:air:{agentHost}:agents:{label} lineage handle, used by both this
// catalog and the ARD Finder's search projection
// (internal/finder/project/urn.go). Sharing the implementation is what
// makes "search results and the published catalog hand consumers one
// identifier per agent" structural rather than two mirrored copies.
// Successive versions of one logical agent share the handle by sharing a
// display name; a false second result means no usable label exists and
// the caller gates on it (ReasonNoLabel).
func mintURN(agentHost, sanitizedDisplayName string) (string, bool) {
	return ard.MintURN(agentHost, sanitizedDisplayName)
}

// buildPublisher builds the Publisher block (§3.7). ANS has no verified
// org name, so identifier and displayName are both the agentHost (honest,
// no unverified claim) and the identity is DNS-anchored.
func buildPublisher(agentHost string) *Publisher {
	host := sanitizeText(agentHost)
	return &Publisher{
		Identifier:   host,
		DisplayName:  host,
		IdentityType: identityTypeDNS,
	}
}

// buildMetadata builds the entry metadata block (§5.3). BadgeURL is
// included only when a TL base URL is configured.
func buildMetadata(reg *domain.AgentRegistration, tlBaseURL string) *Metadata {
	m := &Metadata{
		AnsName:   sanitizeText(reg.AnsName.String()),
		AgentHost: sanitizeText(reg.AnsName.AgentHost()),
	}
	if tlBaseURL != "" {
		m.BadgeURL = badgeURL(tlBaseURL, reg.AgentID)
	}
	return m
}

// buildTrustManifest builds the trust manifest (§5). Identity MUST equal
// the entry's identifier (§5.1). The ANS-Registration SCITT-receipt
// attestation is added only when a TL base URL is configured; otherwise
// the manifest carries identity alone (attestations is optional per the
// 2026-06-11 draft §5.2), avoiding a malformed receipt URI.
func buildTrustManifest(identifier, agentID, tlBaseURL string) *TrustManifest {
	tm := &TrustManifest{Identity: identifier}
	if tlBaseURL != "" {
		tm.Attestations = []Attestation{{
			Type:      attestationType,
			URI:       receiptURL(tlBaseURL, agentID),
			MediaType: receiptMediaType,
		}}
	}
	return tm
}

// collectTags flattens and de-duplicates the tags across an endpoint's
// functions, sanitizing each (§3.1 tags pass-through). Order is
// first-seen; sanitizeTags drops empties and duplicates.
func collectTags(functions []domain.AgentFunction) []string {
	if len(functions) == 0 {
		return nil
	}
	var tags []string
	for _, fn := range functions {
		tags = append(tags, fn.Tags...)
	}
	return sanitizeTags(tags)
}

// badgeURL is the TL badge surface for an agent: <tl>/v1/agents/{agentId}
// (TL API spec). Built from already-validated config, not registrant
// input, so it does not pass the agentHost-bound URL policy.
func badgeURL(tlBaseURL, agentID string) string {
	return strings.TrimRight(tlBaseURL, "/") + "/v1/agents/" + agentID
}

// receiptURL is the SCITT-receipt surface for an agent:
// <tl>/v1/agents/{agentId}/receipt (TL API spec §5.2).
func receiptURL(tlBaseURL, agentID string) string {
	return badgeURL(tlBaseURL, agentID) + "/receipt"
}

// rfc3339 formats t as an RFC 3339 UTC timestamp, or "" when t is zero so
// the caller can omit a missing updatedAt cleanly.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
