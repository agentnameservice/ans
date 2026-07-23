package project

import (
	"testing"

	"github.com/agentnameservice/ans/internal/finder/feed"
)

// White-box tests for unexported helpers whose defensive branches are
// not reachable through FromEvent under the feed.Validate invariant
// (FromEvent only ever projects entries from one event — a single URN —
// and only ever constructs the well-known fallback from an
// already-validated host). Testing the helpers directly with crafted
// inputs exercises those branches honestly rather than annotating them
// as dead code.

// TestSortEntries_IdentifierTieBreak covers the identifier comparison in
// sortEntries. Within one FromEvent call every entry shares the minted
// URN, so this branch never fires there; a registry that merges entries
// across events would rely on it, so it is tested directly.
func TestSortEntries_IdentifierTieBreak(t *testing.T) {
	t.Parallel()
	entries := []ProjectedEntry{
		{Entry: Entry{Identifier: "urn:air:b.example.com:agents:z", Type: "t", URL: "u"}},
		{Entry: Entry{Identifier: "urn:air:a.example.com:agents:a", Type: "t", URL: "u"}},
	}
	sortEntries(entries)
	if entries[0].Identifier != "urn:air:a.example.com:agents:a" {
		t.Fatalf("identifier sort: got %q first", entries[0].Identifier)
	}
}

// TestSelectURL_FallbackFailsPolicy covers the well-known fallback
// failure branch in selectURL. FromEvent always builds the fallback
// from a host already validated by feed.Validate, so the constructed
// URL always passes; passing a host that would not parse cleanly into a
// hostname exercises the fail-closed branch directly.
func TestSelectURL_FallbackFailsPolicy(t *testing.T) {
	t.Parallel()
	// attestedHost with a slash makes the constructed fallback URL's
	// hostname differ from attestedHost, so validateEmittedURL fails.
	ep := feed.AgentEndpoint{Protocol: feed.ProtocolMCP} // no metaDataUrl
	url, skip := selectURL(ep, "bad/host", wellKnownMCP, Options{})
	if skip == nil {
		t.Fatal("expected a Skip from a fallback that fails policy")
	}
	if skip.Kind != SkipInvalidURL {
		t.Errorf("skip kind: got %q, want %q", skip.Kind, SkipInvalidURL)
	}
	if url != "" {
		t.Errorf("expected empty url on skip, got %q", url)
	}
}

// TestValidateEmittedURL_Empty covers the empty-input guard directly.
func TestValidateEmittedURL_Empty(t *testing.T) {
	t.Parallel()
	if _, err := validateEmittedURL("   ", "host.example.com", false); err == nil {
		t.Fatal("expected error on empty url")
	}
}

// TestSanitizeText_EmptyShortCircuit covers the empty-input fast path.
func TestSanitizeText_EmptyShortCircuit(t *testing.T) {
	t.Parallel()
	if got := sanitizeText(""); got != "" {
		t.Fatalf("sanitizeText(\"\") = %q, want empty", got)
	}
}

// TestLabelize_Empty covers labelize's empty-after-trim path directly.
func TestLabelize_Empty(t *testing.T) {
	t.Parallel()
	if got := labelize("   "); got != "" {
		t.Fatalf("labelize whitespace = %q, want empty", got)
	}
}
