package sqlitefinder_test

import (
	"context"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/store/sqlitefinder"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

// newStore opens an in-memory store for one test and closes it on
// cleanup.
func newStore(t *testing.T) *sqlitefinder.Store {
	t.Helper()
	s, err := sqlitefinder.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// activeEntry builds an Active ProjectedEntry for one (host, label,
// type, url) with the given functions projected into capabilities/tags.
func activeEntry(host, label, typ, url string, opts ...func(*project.ProjectedEntry)) project.ProjectedEntry {
	urn := "urn:ai:" + host + ":agents:" + label
	pe := project.ProjectedEntry{
		Entry: project.Entry{
			Identifier:  urn,
			DisplayName: label,
			Type:        typ,
			URL:         url,
			TrustManifest: &project.TrustManifest{
				Identity:     "https://" + host,
				IdentityType: "https",
				Attestations: []project.Attestation{{
					Type:      "ANS-Registration",
					URI:       "https://tl.example.org/v1/agents/" + label + "/receipt",
					MediaType: "application/scitt-receipt+cose",
				}},
			},
		},
		Lifecycle: project.LifecycleActive,
		AgentID:   "agent-" + label,
		AnsName:   "ans://v1.0.0." + host,
		LogID:     "log-" + label,
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	for _, o := range opts {
		o(&pe)
	}
	return pe
}

func withDisplay(name, desc string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) {
		pe.Entry.DisplayName = name
		pe.Entry.Description = desc
	}
}

func withTags(tags ...string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.Entry.Tags = tags }
}

func withCaps(caps ...string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.Entry.Capabilities = caps }
}

func withCreated(ts string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.CreatedAt = ts }
}

// withAnsName overrides the per-registration ansName key. Two agents that
// share a publisher host but are distinct registrations have distinct
// ansNames (they differ by version: ans://v1.0.0.host vs ans://v2.0.0.host).
// The store keys its replace-by-ansName semantics on this, so distinct
// agents under one host MUST carry distinct ansNames.
func withAnsName(ansName string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.AnsName = ansName }
}

func withExpires(ts string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.ExpiresAt = ts }
}

func tombstone(host, label, ansName, ts string, lc project.Lifecycle) project.ProjectedEntry {
	return project.ProjectedEntry{
		Lifecycle: lc,
		AgentID:   "agent-" + label,
		AnsName:   ansName,
		LogID:     "tomb-" + label,
		CreatedAt: ts,
	}
}

func mustApply(t *testing.T, s *sqlitefinder.Store, entries ...project.ProjectedEntry) {
	t.Helper()
	if _, err := s.Apply(context.Background(), entries); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

var farFuture = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

func search(t *testing.T, s *sqlitefinder.Store, q index.SearchQuery) index.SearchResults {
	t.Helper()
	res, err := s.Search(context.Background(), q, farFuture)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	return res
}

// ── Apply + Search basics ────────────────────────────────────────────

func TestApply_Search_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("a.example.com", "flight-booker", "application/mcp-server+json",
			"https://a.example.com/.well-known/mcp.json",
			withDisplay("Flight Booker", "Books flights worldwide"),
			withCaps("Search Flights", "Book Flight"),
			withTags("travel", "booking")),
	)

	res := search(t, s, index.SearchQuery{Text: "flight", Limit: 10})
	if len(res.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(res.Results))
	}
	got := res.Results[0]
	if got.Entry.Identifier != "urn:ai:a.example.com:agents:flight-booker" {
		t.Errorf("identifier: %q", got.Entry.Identifier)
	}
	if got.Entry.DisplayName != "Flight Booker" {
		t.Errorf("displayName: %q", got.Entry.DisplayName)
	}
	if got.Score != 100 {
		t.Errorf("single result should score 100, got %d", got.Score)
	}
	// The full entry round-trips, including trust manifest.
	if got.Entry.TrustManifest == nil || len(got.Entry.TrustManifest.Attestations) != 1 {
		t.Errorf("trust manifest lost in round-trip: %+v", got.Entry.TrustManifest)
	}
}

func TestSearch_MatchesDescriptionAndCapabilitiesAndTags(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("a.example.com", "agent-a", "application/mcp-server+json", "https://a.example.com/.well-known/mcp.json",
			withDisplay("Alpha", "handles invoices"), withCaps("Reconcile Ledger"), withTags("finance")),
	)
	cases := map[string]string{
		"display":      "Alpha",
		"description":  "invoices",
		"capabilities": "Reconcile",
		"tags":         "finance",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			res := search(t, s, index.SearchQuery{Text: text, Limit: 10})
			if len(res.Results) != 1 {
				t.Fatalf("%s: got %d results, want 1", name, len(res.Results))
			}
		})
	}
}

func TestSearch_EmptyTextMatchesAll(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x"),
		activeEntry("b.example.com", "b", "application/a2a-agent-card+json", "https://b.example.com/y"),
	)
	res := search(t, s, index.SearchQuery{Text: "", Limit: 10})
	if len(res.Results) != 2 {
		t.Fatalf("empty text should match all, got %d", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Score != 100 {
			t.Errorf("match-all entries score 100, got %d", r.Score)
		}
	}
}

// ── FTS injection / sanitization ─────────────────────────────────────

func TestSearch_FTSDoesNotErrorOnHostileInput(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
			withDisplay("Weather Agent", "forecasts")),
	)
	// Raw FTS5 metacharacters must never reach the engine as syntax — a
	// hostile query is quoted into literal terms, so it returns a result
	// set (possibly empty) rather than raising a SQL/FTS parse error.
	for _, q := range []string{
		`"unterminated`,
		`NEAR(a b)`,
		`col:weather`,
		`weather AND forecasts`,
		`{malformed`,
		`a"b"c`,
	} {
		t.Run(q, func(t *testing.T) {
			if _, err := s.Search(context.Background(), index.SearchQuery{Text: q, Limit: 10}, farFuture); err != nil {
				t.Fatalf("query %q errored (must be sanitized, not fail): %v", q, err)
			}
		})
	}
}

func TestSearch_OperatorTokensNotInterpreted(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// Two disjoint rows. An UNsanitized "weather OR forecast" would use the
	// FTS5 OR operator and match BOTH. Sanitized, it is the literal phrase
	// of three tokens (weather, or, forecast) AND-ed — matching NEITHER,
	// because no single row contains all three.
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
			withDisplay("Weather", "weather only")),
		activeEntry("b.example.com", "b", "application/mcp-server+json", "https://b.example.com/y",
			withDisplay("Forecast", "forecast only")),
	)
	res := search(t, s, index.SearchQuery{Text: "weather OR forecast", Limit: 10})
	if len(res.Results) != 0 {
		t.Fatalf("OR must be a literal token, not an operator; got %d results", len(res.Results))
	}
	// Sanity: each literal term alone still matches its row.
	if got := search(t, s, index.SearchQuery{Text: "weather", Limit: 10}); len(got.Results) != 1 {
		t.Errorf("literal 'weather' should match 1 row, got %d", len(got.Results))
	}
}

func TestSearch_LiteralMultiTokenIsAND(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
			withDisplay("Flight Booker", "books flights")),
		activeEntry("b.example.com", "b", "application/mcp-server+json", "https://b.example.com/y",
			withDisplay("Flight Tracker", "tracks status")),
	)
	// Both tokens must be present (implicit AND), so only the booker matches.
	res := search(t, s, index.SearchQuery{Text: "flight books", Limit: 10})
	if len(res.Results) != 1 || res.Results[0].Entry.DisplayName != "Flight Booker" {
		t.Fatalf("multi-token AND failed: %+v", res.Results)
	}
}

// ── Scoring + ordering ───────────────────────────────────────────────

func TestSearch_ScoreNormalizationAndOrder(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// One row mentions "booking" three times, another once → different bm25.
	mustApply(t, s,
		activeEntry("a.example.com", "strong", "application/mcp-server+json", "https://a.example.com/x",
			withDisplay("Booking Booking", "booking booking booking")),
		activeEntry("b.example.com", "weak", "application/mcp-server+json", "https://b.example.com/y",
			withDisplay("Misc", "one booking here")),
	)
	res := search(t, s, index.SearchQuery{Text: "booking", Limit: 10})
	if len(res.Results) != 2 {
		t.Fatalf("got %d, want 2", len(res.Results))
	}
	// Strongest match ranked first with score 100; weakest 0.
	if res.Results[0].Score != 100 {
		t.Errorf("top score: got %d want 100", res.Results[0].Score)
	}
	if res.Results[1].Score != 0 {
		t.Errorf("bottom score: got %d want 0", res.Results[1].Score)
	}
	if res.Results[0].Entry.DisplayName != "Booking Booking" {
		t.Errorf("order: top is %q", res.Results[0].Entry.DisplayName)
	}
}

func TestSearch_DeterministicTieBreak(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// Same display text → identical bm25 → tie broken by identifier.
	mustApply(t, s,
		activeEntry("z.example.com", "zeta", "application/mcp-server+json", "https://z.example.com/x",
			withDisplay("Same Name", "same")),
		activeEntry("a.example.com", "alpha", "application/mcp-server+json", "https://a.example.com/y",
			withDisplay("Same Name", "same")),
	)
	res := search(t, s, index.SearchQuery{Text: "same", Limit: 10})
	if len(res.Results) != 2 {
		t.Fatalf("got %d", len(res.Results))
	}
	if res.Results[0].Entry.Identifier >= res.Results[1].Entry.Identifier {
		t.Errorf("tie-break not by identifier asc: %q then %q",
			res.Results[0].Entry.Identifier, res.Results[1].Entry.Identifier)
	}
}

// ── Pagination ───────────────────────────────────────────────────────

func TestSearch_Pagination(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	for _, label := range []string{"a", "b", "c", "d", "e"} {
		mustApply(t, s, activeEntry(label+".example.com", label,
			"application/mcp-server+json", "https://"+label+".example.com/x",
			withDisplay("Common", "common term")))
	}
	page1 := search(t, s, index.SearchQuery{Text: "common", Limit: 2, Offset: 0})
	if len(page1.Results) != 2 || !page1.HasMore || page1.NextOffset != 2 {
		t.Fatalf("page1: results=%d hasMore=%v next=%d", len(page1.Results), page1.HasMore, page1.NextOffset)
	}
	page3 := search(t, s, index.SearchQuery{Text: "common", Limit: 2, Offset: 4})
	if len(page3.Results) != 1 || page3.HasMore {
		t.Fatalf("page3: results=%d hasMore=%v", len(page3.Results), page3.HasMore)
	}
	// Offset past the end → empty page, no error, no more.
	beyond := search(t, s, index.SearchQuery{Text: "common", Limit: 2, Offset: 99})
	if len(beyond.Results) != 0 || beyond.HasMore {
		t.Fatalf("beyond: results=%d hasMore=%v", len(beyond.Results), beyond.HasMore)
	}
}

// ── Filters ──────────────────────────────────────────────────────────

// seedFiltered registers three distinct agents. "a" and "c" share the
// publisher host a.example.com but are SEPARATE registrations (distinct
// ansNames — they would differ by version in production), which is the
// only way two agents can share a publisher; the store's
// replace-by-ansName semantics require each registration to own a
// distinct ansName.
func seedFiltered(t *testing.T, s *sqlitefinder.Store) {
	t.Helper()
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
			withAnsName("ans://v1.0.0.a.example.com"),
			withDisplay("Alpha", "x"), withTags("finance", "travel"), withCaps("Pay")),
		activeEntry("b.example.com", "b", "application/a2a-agent-card+json", "https://b.example.com/y",
			withAnsName("ans://v1.0.0.b.example.com"),
			withDisplay("Beta", "x"), withTags("travel"), withCaps("Fly")),
		activeEntry("a.example.com", "c", "application/a2a-agent-card+json", "https://a.example.com/z",
			withAnsName("ans://v2.0.0.a.example.com"),
			withDisplay("Gamma", "x"), withTags("finance"), withCaps("Pay")),
	)
}

func TestSearch_Filters(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		filter index.Filter
		want   int
	}{
		"by type":             {index.Filter{"type": {"application/mcp-server+json"}}, 1},
		"by type OR":          {index.Filter{"type": {"application/mcp-server+json", "application/a2a-agent-card+json"}}, 3},
		"by tag":              {index.Filter{"tags": {"finance"}}, 2},
		"by tag OR":           {index.Filter{"tags": {"finance", "travel"}}, 3},
		"by capability":       {index.Filter{"capabilities": {"Pay"}}, 2},
		"by publisher":        {index.Filter{"publisher": {"a.example.com"}}, 2},
		"by attestation type": {index.Filter{"trustManifest.attestations.type": {"ANS-Registration"}}, 3},
		"AND across keys":     {index.Filter{"publisher": {"a.example.com"}, "tags": {"finance"}}, 2},
		"AND narrows":         {index.Filter{"type": {"application/a2a-agent-card+json"}, "tags": {"finance"}}, 1},
		"no match":            {index.Filter{"tags": {"nonexistent"}}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStore(t)
			seedFiltered(t, s)
			res := search(t, s, index.SearchQuery{Text: "", Filter: tc.filter, Limit: 50})
			if len(res.Results) != tc.want {
				t.Errorf("filter %v: got %d, want %d", tc.filter, len(res.Results), tc.want)
			}
		})
	}
}

func TestSearch_TextAndFilterCompose(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	seedFiltered(t, s)
	// "Alpha" matches one row; tag finance also matches it → 1.
	res := search(t, s, index.SearchQuery{Text: "Alpha", Filter: index.Filter{"tags": {"finance"}}, Limit: 50})
	if len(res.Results) != 1 {
		t.Fatalf("text+filter compose: got %d, want 1", len(res.Results))
	}
}

// ── Expiry ───────────────────────────────────────────────────────────

func TestSearch_ExpiredExcluded(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s,
		activeEntry("live.example.com", "live", "application/mcp-server+json", "https://live.example.com/x",
			withDisplay("Live", "live"), withExpires("2099-01-01T00:00:00Z")),
		activeEntry("dead.example.com", "dead", "application/mcp-server+json", "https://dead.example.com/x",
			withDisplay("Dead", "dead"), withExpires("2020-01-01T00:00:00Z")),
		activeEntry("never.example.com", "never", "application/mcp-server+json", "https://never.example.com/x",
			withDisplay("Never", "never")), // no expiry
	)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	res, err := s.Search(context.Background(), index.SearchQuery{Text: "", Limit: 50}, now)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("expired entry should be excluded: got %d, want 2", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Entry.DisplayName == "Dead" {
			t.Errorf("expired Dead entry leaked into results")
		}
	}
}

// ── Upsert / idempotency ─────────────────────────────────────────────

func TestApply_Idempotent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	e := activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Alpha", "alpha"), withTags("t1"), withCaps("c1"))
	mustApply(t, s, e)
	mustApply(t, s, e) // replay
	res := search(t, s, index.SearchQuery{Text: "alpha", Limit: 10})
	if len(res.Results) != 1 {
		t.Fatalf("idempotent apply should keep 1 row, got %d", len(res.Results))
	}
	// Side-tables must not have doubled — a tag filter still matches once.
	tagRes := search(t, s, index.SearchQuery{Filter: index.Filter{"tags": {"t1"}}, Limit: 10})
	if len(tagRes.Results) != 1 {
		t.Fatalf("tag filter after replay: got %d, want 1", len(tagRes.Results))
	}
}

func TestApply_UpsertReplacesContent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Old Name", "old desc"), withTags("oldtag")))
	// Re-register same key with new content.
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("New Name", "new desc"), withTags("newtag")))

	if got := search(t, s, index.SearchQuery{Text: "Old", Limit: 10}); len(got.Results) != 0 {
		t.Errorf("old content still searchable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Text: "New", Limit: 10}); len(got.Results) != 1 {
		t.Errorf("new content not searchable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Filter: index.Filter{"tags": {"oldtag"}}, Limit: 10}); len(got.Results) != 0 {
		t.Errorf("old tag still filterable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Filter: index.Filter{"tags": {"newtag"}}, Limit: 10}); len(got.Results) != 1 {
		t.Errorf("new tag not filterable: %d", len(got.Results))
	}
}

func TestApply_FanOutSharesAnsName(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// One registration → two endpoints (a2a + mcp), same ansName.
	const ansName = "ans://v1.0.0.a.example.com"
	a2a := activeEntry("a.example.com", "a", "application/a2a-agent-card+json", "https://a.example.com/a2a", withDisplay("Agent", "x"))
	mcp := activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/mcp", withDisplay("Agent", "x"))
	mustApply(t, s, a2a, mcp)
	if got := search(t, s, index.SearchQuery{Text: "Agent", Limit: 10}); len(got.Results) != 2 {
		t.Fatalf("fan-out should yield 2 rows, got %d", len(got.Results))
	}
	// A tombstone on the shared ansName suppresses both.
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))
	if got := search(t, s, index.SearchQuery{Text: "Agent", Limit: 10}); len(got.Results) != 0 {
		t.Fatalf("tombstone should suppress both endpoints, got %d", len(got.Results))
	}
}

// TestApply_DuplicateTypeURLInOneEventDoesNotWedge is the NEW-1 regression
// guard: an event can legitimately project two entries with the SAME
// (type, url) — two same-protocol endpoints that both omit metaDataUrl
// resolve to the identical well-known fallback URL. Inserting both would
// violate UNIQUE(ans_name,type,url) and fail the whole page, wedging
// ingestion on a valid registration. Apply must fold the duplicate
// (last-write-wins) and succeed.
func TestApply_DuplicateTypeURLInOneEventDoesNotWedge(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const url = "https://a.example.com/.well-known/mcp.json"
	// Two entries, same ansName/logId (one event), same (type, url) — what
	// two metaDataUrl-less MCP endpoints project to. The second carries
	// distinct content so we can prove last-write-wins.
	e1 := activeEntry("a.example.com", "a", "application/mcp-server+json", url,
		withDisplay("First", "first desc"), withCaps("Cap One"))
	e2 := activeEntry("a.example.com", "a", "application/mcp-server+json", url,
		withDisplay("Second", "second desc"), withCaps("Cap Two"))

	if _, err := s.Apply(context.Background(), []project.ProjectedEntry{e1, e2}); err != nil {
		t.Fatalf("duplicate (type,url) in one event must not error: %v", err)
	}

	// Exactly one row survives, and it's the LAST (last-write-wins).
	res := search(t, s, index.SearchQuery{Text: "", Limit: 10})
	if len(res.Results) != 1 {
		t.Fatalf("expected exactly 1 row after dedup, got %d", len(res.Results))
	}
	if res.Results[0].Entry.DisplayName != "Second" {
		t.Errorf("last-write-wins: got %q, want Second", res.Results[0].Entry.DisplayName)
	}
	// The first entry's content must not survive (no stale row/FTS/side).
	if got := search(t, s, index.SearchQuery{Text: "first", Limit: 10}); len(got.Results) != 0 {
		t.Errorf("first (superseded) entry still searchable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Filter: index.Filter{"capabilities": {"Cap One"}}, Limit: 10}); len(got.Results) != 0 {
		t.Errorf("first entry's capability still filterable: %d", len(got.Results))
	}
}

// TestApply_RenewReplacesFullRowSet is the H1 regression guard: an Active
// event is the COMPLETE row set for its ansName at that log position, so a
// renewal that changes or drops an endpoint must NOT leave the old row
// discoverable. The old upsert-by-(ans_name,type,url) could only add rows.
func TestApply_RenewReplacesFullRowSet(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const host = "a.example.com"

	// v1: two MCP endpoints — one explicit URL, one well-known fallback URL.
	regA := activeEntry(host, "a", "application/mcp-server+json",
		"https://a.example.com/.well-known/mcp.json", withDisplay("Agent", "v1 desc"))
	regB := activeEntry(host, "a", "application/mcp-server+json",
		"https://a.example.com/mcp-explicit.json", withDisplay("Agent", "v1 desc"))
	mustApply(t, s, regA, regB)
	if got := search(t, s, index.SearchQuery{Text: "Agent", Limit: 10}); len(got.Results) != 2 {
		t.Fatalf("v1 should index 2 endpoints, got %d", len(got.Results))
	}

	// Renewal (same ansName, newer createdAt): keeps one URL, CHANGES the
	// other, and updates the description. The complete new set is exactly
	// these two rows; the old "/mcp-explicit.json" row must be gone.
	renA := activeEntry(host, "a", "application/mcp-server+json",
		"https://a.example.com/.well-known/mcp.json",
		withDisplay("Agent", "v2 desc"), withCreated("2025-06-01T00:00:00Z"))
	renC := activeEntry(host, "a", "application/mcp-server+json",
		"https://a.example.com/mcp-renamed.json",
		withDisplay("Agent", "v2 desc"), withCreated("2025-06-01T00:00:00Z"))
	mustApply(t, s, renA, renC)

	got := search(t, s, index.SearchQuery{Text: "Agent", Limit: 10})
	if len(got.Results) != 2 {
		t.Fatalf("after renew expected exactly 2 rows, got %d", len(got.Results))
	}
	urls := map[string]bool{}
	for _, r := range got.Results {
		urls[r.Entry.URL] = true
		if r.Entry.Description != "v2 desc" {
			t.Errorf("stale description survived: %q", r.Entry.Description)
		}
	}
	if urls["https://a.example.com/mcp-explicit.json"] {
		t.Error("dropped endpoint URL is still discoverable after renewal")
	}
	if !urls["https://a.example.com/.well-known/mcp.json"] || !urls["https://a.example.com/mcp-renamed.json"] {
		t.Errorf("expected exactly the renewed URL set, got %v", urls)
	}
	// The old description must not be searchable at all.
	if r := search(t, s, index.SearchQuery{Text: "v1", Limit: 10}); len(r.Results) != 0 {
		t.Errorf("stale v1 content still searchable: %d", len(r.Results))
	}
}

// TestApply_ReplayDoesNotUnRevoke is the M4 regression guard: once a
// REVOKED has tombstoned an ansName, replaying the older REGISTERED event
// (e.g. a duplicate feed delivery, or a re-fetch after a transient error)
// must NOT re-surface the agent. The store skips an Active set when a
// newer-or-equal tombstone already covers the ansName.
func TestApply_ReplayDoesNotUnRevoke(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"

	register := activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x",
		withAnsName(ansName), withDisplay("Reborn", "should stay buried"),
		withCreated("2025-01-01T00:00:00Z"))

	// Normal order: register, then a newer revoke tombstones it.
	mustApply(t, s, register)
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))
	if got := search(t, s, index.SearchQuery{Text: "Reborn", Limit: 10}); len(got.Results) != 0 {
		t.Fatalf("revoke should have suppressed the agent, got %d", len(got.Results))
	}

	// Replay the OLDER register event — must stay buried under the newer tombstone.
	mustApply(t, s, register)
	if got := search(t, s, index.SearchQuery{Text: "Reborn", Limit: 10}); len(got.Results) != 0 {
		t.Fatalf("replay of an older REGISTERED event un-revoked the agent: %d results", len(got.Results))
	}
}

// TestApply_TombstoneNoOpReported is the M7 guard: a revoke whose
// created_at is older than the Active registration suppresses nothing
// (clock step-back) but the agent stays discoverable, so Apply must
// report it for the caller to WARN on.
func TestApply_TombstoneNoOpReported(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x", withAnsName(ansName),
		withDisplay("Alpha", "alpha"), withCreated("2025-03-01T00:00:00Z")))

	// Revoke dated BEFORE the registration → suppresses zero rows.
	report, err := s.Apply(context.Background(), []project.ProjectedEntry{
		tombstone("a.example.com", "a", ansName, "2025-01-01T00:00:00Z", project.LifecycleRevoked),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(report.TombstoneNoOps) != 1 {
		t.Fatalf("expected 1 tombstone no-op report, got %d", len(report.TombstoneNoOps))
	}
	if report.TombstoneNoOps[0].AnsName != ansName {
		t.Errorf("no-op report ansName: %q", report.TombstoneNoOps[0].AnsName)
	}
	// The agent is indeed still discoverable (the WARN is justified).
	if got := search(t, s, index.SearchQuery{Text: "alpha", Limit: 10}); len(got.Results) != 1 {
		t.Errorf("expected the agent to remain active, got %d", len(got.Results))
	}
}

// TestApply_TombstoneEffectiveNotReported confirms the no-op report fires
// ONLY when rows remain Active — an effective revoke reports nothing.
func TestApply_TombstoneEffectiveNotReported(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json",
		"https://a.example.com/x", withAnsName(ansName),
		withDisplay("Alpha", "alpha"), withCreated("2025-01-01T00:00:00Z")))
	report, err := s.Apply(context.Background(), []project.ProjectedEntry{
		tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(report.TombstoneNoOps) != 0 {
		t.Errorf("effective revoke must not report a no-op, got %+v", report.TombstoneNoOps)
	}
}

// ── Tombstones ───────────────────────────────────────────────────────

func TestApply_TombstoneSuppresses(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Alpha", "alpha"), withTags("t1"), withCreated("2025-01-01T00:00:00Z")))
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))

	if got := search(t, s, index.SearchQuery{Text: "alpha", Limit: 10}); len(got.Results) != 0 {
		t.Errorf("revoked entry still text-searchable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Filter: index.Filter{"tags": {"t1"}}, Limit: 10}); len(got.Results) != 0 {
		t.Errorf("revoked entry still tag-filterable: %d", len(got.Results))
	}
	if got := search(t, s, index.SearchQuery{Text: "", Limit: 10}); len(got.Results) != 0 {
		t.Errorf("revoked entry still in match-all: %d", len(got.Results))
	}
}

func TestApply_StaleTombstoneDoesNotSuppressNewer(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	// A registration created 2025-03 ...
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Fresh", "fresh"), withCreated("2025-03-01T00:00:00Z")))
	// ... must NOT be suppressed by an out-of-order revoke dated 2025-01.
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-01-01T00:00:00Z", project.LifecycleRevoked))
	if got := search(t, s, index.SearchQuery{Text: "Fresh", Limit: 10}); len(got.Results) != 1 {
		t.Fatalf("stale tombstone wrongly suppressed newer registration: %d", len(got.Results))
	}
}

func TestApply_DeprecatedSuppresses(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Alpha", "alpha"), withCreated("2025-01-01T00:00:00Z")))
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleDeprecated))
	if got := search(t, s, index.SearchQuery{Text: "alpha", Limit: 10}); len(got.Results) != 0 {
		t.Errorf("deprecated entry still searchable: %d", len(got.Results))
	}
}

func TestApply_ReregisterAfterRevokeRevives(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.a.example.com"
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Alpha", "alpha"), withCreated("2025-01-01T00:00:00Z")))
	mustApply(t, s, tombstone("a.example.com", "a", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))
	// A fresh registration (e.g. renew) revives the agent.
	mustApply(t, s, activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/x",
		withDisplay("Reborn", "reborn"), withCreated("2025-03-01T00:00:00Z")))
	if got := search(t, s, index.SearchQuery{Text: "Reborn", Limit: 10}); len(got.Results) != 1 {
		t.Fatalf("re-registration after revoke should revive: %d", len(got.Results))
	}
}

func TestApply_TombstoneOnUnknownAnsNameNoop(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// Tombstone for an ansName never seen — must not error, must not
	// create a row.
	mustApply(t, s, tombstone("ghost.example.com", "g", "ans://v1.0.0.ghost.example.com",
		"2025-02-01T00:00:00Z", project.LifecycleRevoked))
	if got := search(t, s, index.SearchQuery{Text: "", Limit: 10}); len(got.Results) != 0 {
		t.Fatalf("tombstone created a phantom row: %d", len(got.Results))
	}
}

func TestApply_Empty(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.Apply(context.Background(), nil); err != nil {
		t.Fatalf("empty apply should be a no-op: %v", err)
	}
}

// ── Explore / facets ─────────────────────────────────────────────────

func TestExplore_Facets(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	seedFiltered(t, s) // a:mcp, b:a2a, c:a2a ; publishers a,b,a ; tags finance/travel...
	res, err := s.Explore(context.Background(), index.ExploreQuery{
		Facets: []index.FacetSpec{
			{Field: "type", Limit: 20},
			{Field: "publisher", Limit: 20},
			{Field: "tags", Limit: 20},
		},
	}, farFuture)
	if err != nil {
		t.Fatalf("explore: %v", err)
	}

	typeFacet := res.Facets["type"]
	// a2a appears twice, mcp once → a2a first (count desc).
	if len(typeFacet.Buckets) != 2 {
		t.Fatalf("type buckets: %d", len(typeFacet.Buckets))
	}
	if typeFacet.Buckets[0].Value != "application/a2a-agent-card+json" || typeFacet.Buckets[0].Count != 2 {
		t.Errorf("top type bucket: %+v", typeFacet.Buckets[0])
	}

	pubFacet := res.Facets["publisher"]
	if len(pubFacet.Buckets) != 2 {
		t.Fatalf("publisher buckets: %d", len(pubFacet.Buckets))
	}
	if pubFacet.Buckets[0].Value != "a.example.com" || pubFacet.Buckets[0].Count != 2 {
		t.Errorf("top publisher bucket: %+v", pubFacet.Buckets[0])
	}

	tagFacet := res.Facets["tags"]
	// finance: a,c (2); travel: a,b (2) → both count 2, sorted by value.
	if len(tagFacet.Buckets) != 2 {
		t.Fatalf("tag buckets: %d", len(tagFacet.Buckets))
	}
	if tagFacet.Buckets[0].Value != "finance" {
		t.Errorf("tag bucket value order: %+v", tagFacet.Buckets)
	}
}

func TestExplore_MinCountAndLimitAndOther(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// types: mcp x3, a2a x2, ai-registry x1
	mustApply(t, s,
		activeEntry("a.example.com", "a", "application/mcp-server+json", "https://a.example.com/1"),
		activeEntry("b.example.com", "b", "application/mcp-server+json", "https://b.example.com/1"),
		activeEntry("c.example.com", "c", "application/mcp-server+json", "https://c.example.com/1"),
		activeEntry("d.example.com", "d", "application/a2a-agent-card+json", "https://d.example.com/1"),
		activeEntry("e.example.com", "e", "application/a2a-agent-card+json", "https://e.example.com/1"),
		activeEntry("f.example.com", "f", "application/ai-registry+json", "https://f.example.com/1"),
	)

	t.Run("minCount drops small buckets without counting them as other", func(t *testing.T) {
		res, _ := s.Explore(context.Background(), index.ExploreQuery{
			Facets: []index.FacetSpec{{Field: "type", Limit: 20, MinCount: 2}},
		}, farFuture)
		f := res.Facets["type"]
		if len(f.Buckets) != 2 { // mcp(3), a2a(2); ai-registry(1) suppressed
			t.Fatalf("buckets: %+v", f.Buckets)
		}
		if f.OtherCount != 0 {
			t.Errorf("minCount-suppressed bucket must not count as other: %d", f.OtherCount)
		}
	})

	t.Run("limit pages out buckets into otherCount", func(t *testing.T) {
		res, _ := s.Explore(context.Background(), index.ExploreQuery{
			Facets: []index.FacetSpec{{Field: "type", Limit: 1}},
		}, farFuture)
		f := res.Facets["type"]
		if len(f.Buckets) != 1 || f.Buckets[0].Count != 3 {
			t.Fatalf("limit=1 top bucket: %+v", f.Buckets)
		}
		// a2a(2) + ai-registry(1) beyond the limit → other = 3.
		if f.OtherCount != 3 {
			t.Errorf("otherCount: got %d, want 3", f.OtherCount)
		}
	})
}

func TestExplore_RespectsFilterAndText(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	seedFiltered(t, s)
	// Facet types but only over publisher a.example.com (a:mcp, c:a2a).
	res, _ := s.Explore(context.Background(), index.ExploreQuery{
		Filter: index.Filter{"publisher": {"a.example.com"}},
		Facets: []index.FacetSpec{{Field: "type", Limit: 20}},
	}, farFuture)
	f := res.Facets["type"]
	if len(f.Buckets) != 2 {
		t.Fatalf("filtered facet buckets: %+v", f.Buckets)
	}
	total := 0
	for _, b := range f.Buckets {
		total += b.Count
	}
	if total != 2 {
		t.Errorf("filtered facet total: got %d, want 2", total)
	}
}

func TestExplore_ExcludesExpiredAndRevoked(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const ansName = "ans://v1.0.0.gone.example.com"
	mustApply(t, s,
		activeEntry("live.example.com", "live", "application/mcp-server+json", "https://live.example.com/1"),
		activeEntry("gone.example.com", "gone", "application/mcp-server+json", "https://gone.example.com/1",
			withCreated("2025-01-01T00:00:00Z")),
	)
	mustApply(t, s, tombstone("gone.example.com", "gone", ansName, "2025-02-01T00:00:00Z", project.LifecycleRevoked))
	res, _ := s.Explore(context.Background(), index.ExploreQuery{
		Facets: []index.FacetSpec{{Field: "type", Limit: 20}},
	}, farFuture)
	f := res.Facets["type"]
	if len(f.Buckets) != 1 || f.Buckets[0].Count != 1 {
		t.Fatalf("facet should count only the live entry: %+v", f.Buckets)
	}
}

// ── Cursor ───────────────────────────────────────────────────────────

func TestCursor_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	// Fresh index: empty cursor, zero poll time.
	c, err := s.Cursor(context.Background())
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if c.LastLogID != "" || !c.LastPollOK.IsZero() {
		t.Fatalf("fresh cursor not empty: %+v", c)
	}

	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := s.SaveCursor(context.Background(), index.Cursor{LastLogID: "log-42", LastPollOK: pollAt}); err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	got, err := s.Cursor(context.Background())
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if got.LastLogID != "log-42" {
		t.Errorf("lastLogID: %q", got.LastLogID)
	}
	if !got.LastPollOK.Equal(pollAt) {
		t.Errorf("lastPollOK: got %v, want %v", got.LastPollOK, pollAt)
	}
}

func TestCursor_SaveZeroPollTime(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if err := s.SaveCursor(context.Background(), index.Cursor{LastLogID: "x"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, _ := s.Cursor(context.Background())
	if !got.LastPollOK.IsZero() {
		t.Errorf("zero poll time should persist as zero, got %v", got.LastPollOK)
	}
}
