package project

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// sanitizeText is the single chokepoint every emitted string passes
// through before it enters a catalog entry. It strips two classes of
// rune that turn publisher-asserted text into an attack on whoever
// renders or parses the entry downstream (an LLM orchestrator, a
// terminal, a web UI):
//
//   - Cc — C0/C1 control characters (NUL, ESC, the C1 block). These can
//     smuggle terminal escape sequences or terminate strings early.
//   - bidirectional and zero-width Cf format characters — RLO (U+202E),
//     the isolates (U+2066–U+2069), and the zero-width family (ZWSP
//     U+200B, ZWNJ U+200C, ZWJ U+200D, BOM/ZWNBSP U+FEFF). These can
//     visually reorder or hide text so a rendered string differs from
//     its bytes (the "Trojan Source" class).
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

// isDisallowedRune reports whether r must be stripped by sanitizeText.
// Runes are named by code point rather than written literally so the
// source stays readable and free of the very invisible characters it
// guards against.
func isDisallowedRune(r rune) bool {
	if unicode.Is(unicode.Cc, r) {
		return true
	}
	switch r {
	case 0x202A, // LEFT-TO-RIGHT EMBEDDING
		0x202B, // RIGHT-TO-LEFT EMBEDDING
		0x202C, // POP DIRECTIONAL FORMATTING
		0x202D, // LEFT-TO-RIGHT OVERRIDE
		0x202E, // RIGHT-TO-LEFT OVERRIDE
		0x2066, // LEFT-TO-RIGHT ISOLATE
		0x2067, // RIGHT-TO-LEFT ISOLATE
		0x2068, // FIRST STRONG ISOLATE
		0x2069, // POP DIRECTIONAL ISOLATE
		0x200B, // ZERO WIDTH SPACE
		0x200C, // ZERO WIDTH NON-JOINER
		0x200D, // ZERO WIDTH JOINER
		0x200E, // LEFT-TO-RIGHT MARK
		0x200F, // RIGHT-TO-LEFT MARK
		0xFEFF: // ZERO WIDTH NO-BREAK SPACE / BOM
		return true
	}
	return false
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
//   - the URL parses;
//   - it is absolute with an explicit scheme;
//   - the scheme is https (http only when allowHTTP is set, a dev
//     override);
//   - no userinfo, no query string, no fragment;
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
	if u.RawQuery != "" {
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
