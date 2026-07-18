package project

import "github.com/godaddy/ans/internal/ard"

// mintURN builds the ARD discovery identifier for an Active entry
// (ARDS §4.2.1): urn:air:<agentHost>:agents:<label>.
//
// The derivation lives in internal/ard — the single source shared with
// the RA's published AI Catalog (internal/catalog), so search results
// and the catalog hand consumers ONE lineage identifier per agent. See
// ard.MintURN for the full semantics (lineage handle, host lowering,
// label rules, no-label refusal). agentHost is the attested host,
// already syntax-validated and bound to the ansName by
// feed.EventItem.Validate; an empty label makes the caller Skip the
// event rather than substitute a fallback.
func mintURN(agentHost, sanitizedDisplayName string) (string, bool) {
	return ard.MintURN(agentHost, sanitizedDisplayName)
}

// labelize is ard.Labelize — kept as a package alias because the
// projection tests pin label behavior at this seam.
func labelize(s string) string {
	return ard.Labelize(s)
}
