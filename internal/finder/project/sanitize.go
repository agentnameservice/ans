package project

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// sanitizeText is the single chokepoint every emitted string passes
// through before it enters a catalog entry. It strips two whole Unicode
// general categories of rune that turn publisher-asserted text into an
// attack on whoever renders or parses the entry downstream (an LLM
// orchestrator, a terminal, a web UI):
//
//   - Cc — C0/C1 control characters (NUL, ESC, the C1 block). These can
//     smuggle terminal escape sequences or terminate strings early.
//   - Cf — format characters. This is the superset that covers the
//     bidirectional controls (the embeddings/overrides U+202A–U+202E,
//     the isolates U+2066–U+2069, the marks U+200E/U+200F, and
//     U+061C ARABIC LETTER MARK), the zero-width family (ZWSP U+200B,
//     ZWNJ U+200C, ZWJ U+200D, WORD JOINER U+2060, BOM/ZWNBSP U+FEFF),
//     and the invisible TAG block (U+E0000–U+E007F). These can visually
//     reorder or hide text so a rendered string differs from its bytes
//     (the "Trojan Source" class). Stripping the whole category rather
//     than an enumerated list is deliberate: the wire format freezes
//     now, so a strict superset is safer than a list that can fall
//     behind new format characters.
//
// Ordinary printable runes — including legitimate non-ASCII letters and
// emoji — pass through untouched. The function removes offending runes
// rather than rejecting the whole string, so a single stray control
// character does not erase an otherwise useful display name.
func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isDisallowedRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isDisallowedRune reports whether r is a control (Cc) or format (Cf)
// character that must be stripped from emitted text and rejected in
// emitted URLs. Both are full Unicode general categories; see
// sanitizeText for the threat each covers.
func isDisallowedRune(r rune) bool {
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

// validateEmittedURL is the single gate every URL passes through before
// it enters a catalog entry — the agent's url, the constructed
// well-known fallback, and metadata.agentUrl alike. No URL is ever
// trusted by construction.
//
// The policy mirrors the RA's public-base-url restriction
// (internal/config/config.go validatePublicBaseURL) and the endpoint
// host-match semantics (domain.AgentEndpoint.ValidateHostMatch):
//
//   - the raw string carries no control (Cc) or format (Cf) rune — the
//     same hygiene sanitizeText applies to free text, but for a URL we
//     REJECT fail-closed rather than strip: a URL is structural, and a
//     silently-stripped bidi/zero-width rune would change which host the
//     URL points at;
//   - the URL parses;
//   - it is absolute with an explicit scheme;
//   - the scheme is https (http only when allowHTTP is set, a dev
//     override);
//   - no userinfo, no query string (including a bare trailing "?"), no
//     fragment;
//   - the hostname (port stripped, compared case-insensitively) equals
//     the attested host.
//
// Non-default ports are permitted by design: an agent legitimately
// hosted on a non-443 port is in scope, and the host-equality check
// already binds the URL to the attested FQDN. The returned string is
// the input verbatim on success (the function validates, it does not
// rewrite).
func validateEmittedURL(raw, attestedHost string, allowHTTP bool) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("url is empty")
	}
	for _, r := range raw {
		if isDisallowedRune(r) {
			return "", fmt.Errorf("url %q contains a disallowed control/format rune U+%04X", raw, r)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("url %q does not parse: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("url %q is not absolute", raw)
	}
	switch u.Scheme {
	case "https":
		// always allowed
	case "http":
		if !allowHTTP {
			return "", fmt.Errorf("url %q uses http but AllowHTTP is off", raw)
		}
	default:
		return "", fmt.Errorf("url %q scheme %q not permitted", raw, u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("url %q carries userinfo", raw)
	}
	// RawQuery catches "?a=1"; ForceQuery catches a bare trailing "?"
	// (which url.Parse records with an empty RawQuery), so both are
	// rejected.
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("url %q carries a query string", raw)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("url %q carries a fragment", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host != strings.ToLower(attestedHost) {
		return "", fmt.Errorf(
			"url %q hostname %q does not match attested host %q",
			raw, host, attestedHost,
		)
	}
	return raw, nil
}
