package catalog

import (
	"net/url"
	"strings"
)

// validateEmittedURL enforces the emit-side URL policy (IMPL §3.8) on a
// registrant-supplied URL before it leaves the RA as an entry's `url`. It
// returns the URL to emit (verbatim — a passing URL is never rewritten)
// and true, or "" and false when the URL violates the policy.
//
// The policy is fail-closed: a violating URL causes its endpoint to be
// skipped (§3.6), never emitted, and no URL is ever built by string
// concatenation that bypasses this check. A URL MUST be:
//
//   - absolute (carries a scheme);
//   - https — or http only when allowInsecure is set (a dev-only override);
//   - free of userinfo, query, and fragment;
//   - hosted on agentHost: its host, port-stripped and case-insensitive,
//     MUST equal agentHost. This keeps a poisoned entry from pointing a
//     consumer at a metadata document on a host the agent does not own.
//
// The Transparency-Log badge and receipt URLs are RA-controlled and built
// from already-validated config (PublicBaseURL), not registrant input, so
// they do not pass through this agentHost-bound check.
func validateEmittedURL(raw, agentHost string, allowInsecure bool) (string, bool) {
	if raw == "" || agentHost == "" {
		return "", false
	}
	// Reject — never strip — any control (Cc) or format (Cf) rune anywhere
	// in the raw URL before parsing. url.Parse only rejects ASCII controls,
	// so a bidi override or zero-width rune in the path would otherwise
	// parse cleanly, pass the host pin, and ship verbatim into a document
	// rendered in UIs and LLM contexts. Stripping would silently emit a
	// different URL than the registrant declared; refusal keeps the
	// endpoint out of the catalog instead. Mirrors the Finder's
	// validateEmittedURL (internal/finder/project/sanitize.go).
	if strings.ContainsFunc(raw, isControlOrFormat) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if !u.IsAbs() {
		return "", false
	}
	switch u.Scheme {
	case "https":
		// always allowed
	case "http":
		if !allowInsecure {
			return "", false
		}
	default:
		return "", false
	}
	if u.User != nil {
		return "", false
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", false
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname()) // port-stripped
	if host == "" || host != strings.ToLower(strings.TrimSpace(agentHost)) {
		return "", false
	}
	return raw, true
}
