package sqlitefinder_test

import (
	"testing"

	"github.com/agentnameservice/ans/internal/finder/index"
	"github.com/agentnameservice/ans/internal/finder/project"
)

// TestSearch_PublisherHostTokensMatch proves the publisher host is part
// of the free-text surface: a user who only knows the agent's domain
// finds it even when the display fields share no tokens with the host.
// The seeded entry's displayName/description deliberately avoid every
// host word, so a match can only come from the FTS publisher column.
// unicode61 treats "." as a separator, so "translator.example.com"
// indexes as the tokens translator / example / com.
//
// Query-side, a dotted term is NOT split into independent AND tokens:
// buildMatchQuery quotes each whitespace term whole, and FTS5 treats a
// quoted multi-token string as a PHRASE — sub-tokens adjacent and in
// order within one field. The full host matches its publisher column
// because the tokens sit there in exactly that order; a reordered or
// partial dotted form does not (pinned below and documented in the
// spec's text-matching contract).
func TestSearch_PublisherHostTokensMatch(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("translator.example.com", "v2-demo-agent",
			"application/mcp-server-card+json",
			"https://translator.example.com/.well-known/mcp.json",
			withDisplay("v2-demo-agent", "demo registration target")),
	)

	cases := []struct {
		name string
		text string
		want int
	}{
		{name: "host label alone", text: "translator", want: 1},
		{name: "full host matches as ordered phrase", text: "translator.example.com", want: 1},
		{name: "reordered dotted term is a non-matching phrase", text: "example.translator", want: 0},
		{name: "partial dotted term skipping a label is a non-matching phrase", text: "translator.com", want: 0},
		{name: "space-separated host words match as independent terms", text: "translator example", want: 1},
		{name: "case-insensitive host label", text: "TRANSLATOR", want: 1},
		{name: "host term AND display term compose across columns", text: "translator demo", want: 1},
		{name: "term absent from every column", text: "summarizer", want: 0},
		{name: "host term AND absent term still requires all terms", text: "translator summarizer", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := search(t, s, index.SearchQuery{Text: tc.text, Limit: 10})
			if len(res.Results) != tc.want {
				t.Fatalf("text %q: got %d results, want %d", tc.text, len(res.Results), tc.want)
			}
		})
	}
}

// TestSearch_TombstoneRemovesPublisherFromFTS guards the suppression
// invariant for the new column: after a revoke, the agent's host tokens
// must stop matching — a revoked agent surfacing via its domain would
// defeat the tombstone.
func TestSearch_TombstoneRemovesPublisherFromFTS(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("revocable.example.org", "victim", "application/mcp-server-card+json",
			"https://revocable.example.org/.well-known/mcp.json",
			withDisplay("victim", "will be revoked")),
	)
	if res := search(t, s, index.SearchQuery{Text: "revocable", Limit: 10}); len(res.Results) != 1 {
		t.Fatalf("pre-revoke: got %d results, want 1", len(res.Results))
	}

	mustApply(t, s, tombstone("revocable.example.org", "victim",
		"ans://v1.0.0.revocable.example.org", "2025-06-01T00:00:00Z", project.LifecycleRevoked))

	if res := search(t, s, index.SearchQuery{Text: "revocable", Limit: 10}); len(res.Results) != 0 {
		t.Fatalf("post-revoke: got %d results, want 0 — revoked agent still discoverable by host", len(res.Results))
	}
}
