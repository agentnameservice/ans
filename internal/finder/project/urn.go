package project

import "strings"

// urnNamespace is the fixed hierarchical segment between the publisher
// host and the agent label in a Finder-minted URN. ANS registers
// agents, so every Finder entry lives under the `agents` namespace.
const urnNamespace = "agents"

// mintURN builds the ARD discovery identifier for an Active entry
// (ARDS §4.2.1):
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
// agentHost is the attested host, already syntax-validated and bound to
// the ansName by feed.EventItem.Validate, so it needs no re-validation
// here. The label is the sanitized display name with internal
// whitespace collapsed to single hyphens so the terminal URN segment is
// a stable, parseable short name. An empty label (display name missing
// or sanitized away to nothing) yields a false second result: the
// caller Skips the event rather than substituting any fallback, because
// a URN without a real terminal segment is not a usable discovery
// handle.
func mintURN(agentHost, sanitizedDisplayName string) (string, bool) {
	label := labelize(sanitizedDisplayName)
	if label == "" {
		return "", false
	}
	return "urn:air:" + strings.ToLower(agentHost) + ":" + urnNamespace + ":" + label, true
}

// labelize turns a sanitized display name into a URN terminal segment:
// trim, then collapse each run of whitespace to a single hyphen. It does
// not change case (intra-host label space is publisher-owned) and does
// not otherwise rewrite characters — sanitizeText has already removed
// control and bidi runes upstream.
func labelize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), "-")
}
