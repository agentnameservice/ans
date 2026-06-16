// Package catalog generates AI Catalog artifacts from a registration
// aggregate. It is the single generation seam (IMPL-ai-catalog §10): every
// emitted catalog shape — the per-agent CatalogEntry today, the per-host
// document and population export later — is composed here, so the pending
// IANA churn (the urn:ai NID, the application/ai-catalog+json media type,
// the type/mediaType discriminator rename) lands in one place.
//
// ANS is a producer only: every byte is derived from the RA's own
// registration aggregate. Nothing here is sealed in the Transparency Log
// and nothing new is verified — the artifact's trust comes from the
// ANS-Registration attestation it carries (a SCITT-receipt URI a consumer
// verifies against the TL). The package is pure: no I/O, no clock, no
// global state, so any document can be regenerated from current RA state.
//
// Authoritative shape: the AI Catalog draft of 2026-06-11. Field names,
// the one-of url|data invariant, and the media types follow that draft;
// the projection choices (the urn:ai:{host}:agents:{label} lineage handle,
// the ANS-Registration attestation, the {ansName,agentHost,badgeUrl}
// metadata) follow IMPL-ai-catalog-generation.md.
package catalog

// SpecVersion is the AI Catalog document version this generator emits. It
// is pinned and never overstated (AI Catalog §8.4 producer rule); it
// labels the nested catalog a multi-protocol entry inlines (§3.5) and,
// from slice 2, the per-host and export documents.
const SpecVersion = "1.0"

// Media types and the trust-manifest vocabulary, all from the 2026-06-11
// draft. MediaTypeCatalog discriminates a (possibly nested) catalog
// document; the A2A/MCP values discriminate a single protocol card.
const (
	MediaTypeCatalog = "application/ai-catalog+json"
	mediaTypeA2A     = "application/a2a-agent-card+json"
	mediaTypeMCP     = "application/mcp-server-card+json"

	// attestationType is the trust-manifest attestation that points a
	// consumer at the agent's SCITT receipt on the Transparency Log
	// (IMPL §5.2). It is the only attestation slice 1 emits.
	attestationType  = "ANS-Registration"
	receiptMediaType = "application/scitt-receipt+cose"

	// identityTypeDNS marks the publisher identity as DNS-anchored.
	// Graduates to "did" once an owner links a did:web identity (§9);
	// slice 1 is always "dns".
	identityTypeDNS = "dns"
)

// Entry is one CatalogEntry — a single artifact's record (IMPL §3). The
// same type serves a top-level entry, a multi-protocol outer entry (which
// carries Data instead of URL), and a lean nested child (identifier /
// displayName / mediaType / url only): every non-required field is
// omitempty, so each shape marshals correctly without a separate type.
//
// Field order mirrors the IMPL Appendix B worked examples so emitted JSON
// diffs line-for-line against the spec. A bare Entry is served as
// application/json — it is not itself a catalog document and carries no
// specVersion (§2).
type Entry struct {
	// Identifier is the stable, version-spanning lineage handle
	// urn:ai:{agentHost}:agents:{label} (§3.3) — never the per-version
	// agentId. MUST.
	Identifier string `json:"identifier"`
	// DisplayName is the agent's human-readable name (≤64). MUST.
	DisplayName string `json:"displayName"`
	// Description is a short capability summary (≤150). Optional.
	Description string `json:"description,omitempty"`
	// Version is the bare semver (e.g. "2.1.0"). Required for
	// eligibility (§3.6 Gate 1); absent on lean nested children.
	Version string `json:"version,omitempty"`
	// MediaType discriminates the artifact: an A2A/MCP card media type
	// for a single-protocol entry, or MediaTypeCatalog for a
	// multi-protocol outer entry (§3.5). MUST.
	MediaType string `json:"mediaType"`
	// URL points at the protocol metadata document (the endpoint's
	// metaDataUrl). Exactly one of URL / Data is set per entry (§3.6);
	// a leaf entry uses URL.
	URL string `json:"url,omitempty"`
	// Data inlines a nested catalog of per-protocol children, used only
	// by the multi-protocol outer entry (§3.5). Never raw card bytes —
	// ANS does not retain those.
	Data *NestedCatalog `json:"data,omitempty"`
	// Tags are discovery keywords passed through from the endpoint's
	// functions[].tags. Optional.
	Tags []string `json:"tags,omitempty"`
	// UpdatedAt is an RFC 3339 timestamp of the last lifecycle change.
	// Optional.
	UpdatedAt string `json:"updatedAt,omitempty"`
	// Publisher identifies the publishing entity (§3.7). Optional in
	// the spec; always emitted.
	Publisher *Publisher `json:"publisher,omitempty"`
	// Metadata carries the identifiers a consumer needs to verify
	// (§5.3): ansName, agentHost, badgeUrl. Optional in the spec;
	// always emitted on a top-level entry.
	Metadata *Metadata `json:"metadata,omitempty"`
	// TrustManifest binds the entry to its SCITT-receipt attestation
	// (§5), making it L3-Trusted. Optional in the spec; emitted on a
	// top-level entry (attestations present only when the TL base URL
	// is configured).
	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`
}

// NestedCatalog is the inline document a multi-protocol outer entry holds
// in its Data field (§3.5): a self-contained catalog whose entries are the
// per-protocol children. It carries specVersion because it is a catalog
// document, but no host — it is inline data, never re-fetched.
type NestedCatalog struct {
	SpecVersion string  `json:"specVersion"`
	Entries     []Entry `json:"entries"`
}

// Publisher identifies the entity publishing the artifact (AI Catalog
// §4.6, IMPL §3.7). Identifier and DisplayName are required within a
// Publisher; ANS has no verified org name, so both are the agentHost in
// slice 1 (honest, no unverified claim) and IdentityType is "dns".
type Publisher struct {
	Identifier   string `json:"identifier"`
	DisplayName  string `json:"displayName"`
	IdentityType string `json:"identityType,omitempty"`
}

// Metadata is the entry-level metadata block (IMPL §5.3): plain keys
// carrying the identifiers a consumer verifies against. No logId — the TL
// has no lookup-by-logId route; it is keyed by agentId, which is visible
// in both BadgeURL and the attestation receipt URI.
type Metadata struct {
	// AnsName is the canonical, DNS-resolvable ANS handle
	// (ans://v{ver}.{host}); not derivable from the URN.
	AnsName string `json:"ansName"`
	// AgentHost is the sealed authority a consumer matches the URN's
	// host segment against (§5.2 step 2).
	AgentHost string `json:"agentHost"`
	// BadgeURL is the TL status/card-integrity surface
	// (<tl>/v1/agents/{agentId}). Omitted when no TL base URL is
	// configured.
	BadgeURL string `json:"badgeUrl,omitempty"`
}

// TrustManifest provides verifiable identity and trust metadata for the
// entry (AI Catalog §5). Identity is the only MUST member and MUST equal
// the containing entry's Identifier (§5.1); Attestations is optional and,
// in slice 1, holds exactly the ANS-Registration SCITT-receipt attestation
// when a TL base URL is configured.
type TrustManifest struct {
	Identity     string        `json:"identity"`
	Attestations []Attestation `json:"attestations,omitempty"`
}

// Attestation is one verifiable claim (AI Catalog §5.4). The slice-1
// attestation points at the agent's SCITT receipt on the TL; Type, URI,
// and MediaType are all required. No digest: the receipt proves inclusion
// of the latest sealed event, not the entry's content, so a content digest
// would over-claim what it verifies (§3.2).
type Attestation struct {
	Type      string `json:"type"`
	URI       string `json:"uri"`
	MediaType string `json:"mediaType"`
}
