package handler

import "testing"

// paginateIdentityViews backs both computed-view routes; pin its
// edges (offset past the end, zero limit = all, limit clamps).
func TestPaginateIdentityViews(t *testing.T) {
	t.Parallel()
	views := []int{1, 2, 3, 4, 5}

	if got := paginateIdentityViews(views, 0, 0); len(got) != 5 {
		t.Fatalf("no bounds: %v", got)
	}
	if got := paginateIdentityViews(views, 2, 0); len(got) != 2 || got[0] != 1 {
		t.Fatalf("limit only: %v", got)
	}
	if got := paginateIdentityViews(views, 2, 4); len(got) != 1 || got[0] != 5 {
		t.Fatalf("tail page: %v", got)
	}
	if got := paginateIdentityViews(views, 2, 9); len(got) != 0 {
		t.Fatalf("offset past end: %v", got)
	}
	if got := paginateIdentityViews(views, 99, 1); len(got) != 4 {
		t.Fatalf("oversized limit: %v", got)
	}
}
