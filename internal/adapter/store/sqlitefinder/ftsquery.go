package sqlitefinder

import "strings"

// buildMatchQuery turns untrusted free-text into a safe FTS5 MATCH
// expression. The user's text is NEVER interpreted as FTS5 query syntax:
// FTS5 operators (AND, OR, NOT, NEAR, *, :, ^, parentheses, quotes) in
// the input would otherwise let a caller steer or break the query. Each
// whitespace-separated token is wrapped in double quotes as an FTS5
// string literal, and any double quote inside a token is escaped by
// doubling it (the FTS5 string-literal escape). Tokens are joined with
// spaces, which FTS5 treats as an implicit AND — so "flight booking"
// matches rows containing both terms, ranked by bm25.
//
// An input that is empty or only whitespace yields an empty string; the
// caller treats that as "no text constraint" (match-all) rather than
// running a MATCH at all.
func buildMatchQuery(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(fields))
	for _, tok := range fields {
		quoted = append(quoted, `"`+strings.ReplaceAll(tok, `"`, `""`)+`"`)
	}
	return strings.Join(quoted, " ")
}
