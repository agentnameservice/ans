// Package ard holds the projection rules shared by every surface that
// mints ARD (Agentic Resource Discovery) identifiers from registration
// data. Two independent surfaces project the same registrations — the
// Finder's search results (internal/finder/project) and the RA's
// published AI Catalog (internal/catalog) — and "both hand consumers ONE
// lineage identifier per agent" is a stated invariant. Keeping the
// derivation here makes that invariant structural instead of two
// mirrored copies held in lockstep by comments (which diverged twice
// while they were copies).
package ard

import "strings"

// urnNamespace is the fixed hierarchical segment between the publisher
// host and the agent label in a minted URN. ANS registers agents, so
// every entry lives under the `agents` namespace.
const urnNamespace = "agents"

// MintURN builds the ARD discovery identifier for an agent
// (ARD spec v0.9 §4.2.1):
//
//	urn:air:<agentHost>:agents:<label>
//
// The URN is a LINEAGE HANDLE, not a per-registration key: successive
// versions of the same logical agent (same host + same display name)
// deliberately share it. Per-registration uniqueness is carried in the
// wrapper (AgentID/AnsName/LogID) and in metadata, never in the URN.
// The intra-host label space (everything after the host) is the
// publisher's to manage.
//
// agentHost is the attested host, already syntax-validated upstream; it
// is lowercased here so the publisher segment is canonical. The label is
// the sanitized display name via Labelize. An empty label (display name
// missing or sanitized away to nothing) yields a false second result:
// callers skip or reject the projection rather than substituting any
// fallback, because a URN without a real terminal segment is not a
// usable discovery handle.
func MintURN(agentHost, sanitizedDisplayName string) (string, bool) {
	label := Labelize(sanitizedDisplayName)
	if label == "" {
		return "", false
	}
	return "urn:air:" + strings.ToLower(agentHost) + ":" + urnNamespace + ":" + label, true
}

// Labelize turns a sanitized display name into a URN terminal segment:
// trim, then collapse each run of whitespace to a single hyphen. It does
// not change case (intra-host label space is publisher-owned) and does
// not otherwise rewrite characters — the caller's text sanitizer has
// already removed control and bidi runes upstream.
func Labelize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), "-")
}
