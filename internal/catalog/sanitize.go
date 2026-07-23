package catalog

import (
	"strings"
	"unicode"
)

// sanitizeText strips Unicode control (Cc) and format (Cf) runes from s.
//
// Catalog entries carry registrant-controlled strings (displayName,
// description, tags, version, metadata values) that flow on to AI
// orchestrators and into browser- and LLM-facing documents, so every
// emitted string passes this one chokepoint (IMPL §3.8). The Cc/Cf classes
// cover the steerable runes: the bidi override U+202E, the bidi isolates
// U+2066–U+2069, the zero-width family (U+200B–U+200D, U+FEFF), and NUL.
// Nothing in those classes survives.
//
// Plain printable text (including non-Latin scripts and emoji, which are
// not Cc/Cf) passes through unchanged. The common path — a string with no
// such runes — returns the input without allocating.
func sanitizeText(s string) string {
	if s == "" {
		return s
	}
	if !strings.ContainsFunc(s, isControlOrFormat) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControlOrFormat(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isControlOrFormat reports whether r is a Unicode control (Cc) or format
// (Cf) rune — the steerable classes sanitizeText removes.
func isControlOrFormat(r rune) bool {
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

// sanitizeTags sanitizes each tag, drops any that become empty, and
// de-duplicates while preserving first-seen order. Returns nil when no tag
// survives, so the caller can omitempty a missing Tags array cleanly.
func sanitizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		clean := sanitizeText(t)
		if clean == "" {
			continue
		}
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
