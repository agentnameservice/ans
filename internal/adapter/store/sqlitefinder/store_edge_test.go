package sqlitefinder_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/godaddy/ans/internal/adapter/store/sqlitefinder"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

func TestOpen_FileBackedAndReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "finder.db")

	s1, err := sqlitefinder.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	mustApply(t, s1, activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x", withDisplay("Persisted", "persisted")))
	if err := s1.SaveCursor(context.Background(), index.Cursor{LastLogID: "log-7"}); err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	_ = s1.Close()

	// Reopen the same file: migrations are idempotent, data survives.
	s2, err := sqlitefinder.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if got := search(t, s2, index.SearchQuery{Text: "Persisted", Limit: 10}); len(got.Results) != 1 {
		t.Fatalf("data did not survive reopen: %d results", len(got.Results))
	}
	c, _ := s2.Cursor(context.Background())
	if c.LastLogID != "log-7" {
		t.Errorf("cursor did not survive reopen: %q", c.LastLogID)
	}
}

func TestApply_UnknownLifecycleErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// A lifecycle the projection layer never emits is a programming error
	// and must surface loudly rather than silently no-op.
	_, err := s.Apply(context.Background(), []project.ProjectedEntry{{
		Lifecycle: project.Lifecycle("BOGUS"),
		AnsName:   "ans://v1.0.0.a.example.com",
		AgentID:   "agent-x",
		LogID:     "log-x",
		CreatedAt: "2025-01-01T00:00:00Z",
	}})
	if err == nil {
		t.Fatal("expected error for unknown lifecycle")
	}
}

func TestExplore_UnsupportedFacetFieldErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x", withDisplay("Alpha", "alpha")))
	_, err := s.Explore(context.Background(), index.ExploreQuery{
		Facets: []index.FacetSpec{{Field: "not.a.real.field", Limit: 20}},
	}, farFuture)
	if err == nil {
		t.Fatal("expected error for unsupported facet field")
	}
}

func TestSearch_UnsupportedFilterFieldErrors(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	_, err := s.Search(context.Background(), index.SearchQuery{
		Filter: index.Filter{"not.a.real.field": {"x"}},
		Limit:  10,
	}, farFuture)
	if err == nil {
		t.Fatal("expected error for unsupported filter field")
	}
}

func TestApply_TombstoneWithoutIdentifierHasEmptyPublisher(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// Active entry under publisher a.example.com, then a tombstone whose
	// (absent) identifier yields empty publisher — suppression keys on
	// ansName, not publisher, so it still applies.
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x", withDisplay("Alpha", "alpha"), withCreated("2025-01-01T00:00:00Z")))
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))
	if got := search(t, s, index.SearchQuery{Text: "alpha", Limit: 10}); len(got.Results) != 0 {
		t.Fatalf("tombstone keyed on ansName should suppress regardless of publisher: %d", len(got.Results))
	}
}
