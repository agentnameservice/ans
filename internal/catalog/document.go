package catalog

import (
	"sort"

	"github.com/agentnameservice/ans/internal/domain"
)

// Document is a catalog document (AI Catalog §4.2): the file an Agent
// Hosting Platform publishes at /.well-known/ai-catalog.json. Unlike a
// bare Entry, it carries specVersion and a host object and is served as
// application/ai-catalog+json.
type Document struct {
	SpecVersion string    `json:"specVersion"`
	Host        *HostInfo `json:"host,omitempty"`
	Entries     []Entry   `json:"entries"`
}

// HostInfo identifies the operator of a catalog document (AI Catalog
// §4.3). DisplayName is MUST-present within Host Info (§4.1); for a
// per-host document both fields are the agentHost.
type HostInfo struct {
	Identifier  string `json:"identifier,omitempty"`
	DisplayName string `json:"displayName"`
}

// BuildHostDocument composes the host-complete per-host catalog document
// (§4): one CatalogEntry per catalog-eligible agent registered on
// agentHost. regs is every registration for the host (any version, any
// status), each with its Endpoints populated by the caller.
//
// Inclusion is decided entirely by BuildEntry: a registration appears only
// if it is ACTIVE (sealed in the TL — §8 likewise has AHPs prune
// deprecated/revoked from their well-known file; the population export
// keeps them marked, §7.4), versioned, and has an eligible endpoint (§3.6).
// Everything else is silently absent. Entries are sorted (identifier, then
// version) so the emitted bytes — and therefore the ETag — are stable
// across re-derivations.
func BuildHostDocument(agentHost string, regs []*domain.AgentRegistration, opts Options) Document {
	entries := make([]Entry, 0, len(regs))
	for _, reg := range regs {
		if reg == nil {
			continue
		}
		entry, err := BuildEntry(reg, opts)
		if err != nil {
			// Not catalog-eligible (not ACTIVE, versionless, or no
			// A2A/MCP endpoint with a policy-passing metaDataUrl) → absent.
			continue
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)

	host := sanitizeText(agentHost)
	return Document{
		SpecVersion: SpecVersion,
		Host:        &HostInfo{Identifier: host, DisplayName: host},
		Entries:     entries,
	}
}

// sortEntries orders entries deterministically by identifier then
// version. On a single host the identifier (the lineage handle) is shared
// across versions, so this groups an agent's versions together in a
// stable order — keeping the document bytes, and the ETag, reproducible.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Identifier != entries[j].Identifier {
			return entries[i].Identifier < entries[j].Identifier
		}
		return entries[i].Version < entries[j].Version
	})
}
