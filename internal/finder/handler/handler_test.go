package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/store/sqlitefinder"
	"github.com/godaddy/ans/internal/finder/handler"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

var silent = zerolog.Nop()

const sourceURL = "https://finder.example.org/v1/"

// testServer wires the real handler over a real in-memory index and
// returns an httptest server plus the index for seeding.
func testServer(t *testing.T, cfg handler.Config, rl *handler.RateLimiter, now func() time.Time) (*httptest.Server, index.Catalog) {
	t.Helper()
	store, err := sqlitefinder.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if cfg.SourceURL == "" {
		cfg.SourceURL = sourceURL
	}
	h := handler.New(store, cfg, rl, silent, now)
	r := chi.NewRouter()
	h.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, store
}

func seed(t *testing.T, idx index.Catalog, entries ...project.ProjectedEntry) {
	t.Helper()
	if _, err := idx.Apply(context.Background(), entries); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
}

func activeEntry(host, label, typ, url string, mut ...func(*project.ProjectedEntry)) project.ProjectedEntry {
	pe := project.ProjectedEntry{
		Entry: project.Entry{
			Identifier:  "urn:ai:" + host + ":agents:" + label,
			DisplayName: label,
			Type:        typ,
			URL:         url,
			TrustManifest: &project.TrustManifest{
				Identity:     "https://" + host,
				IdentityType: "https",
				Attestations: []project.Attestation{{Type: "ANS-Registration", URI: "https://tl/x", MediaType: "application/scitt-receipt+cose"}},
			},
		},
		Lifecycle: project.LifecycleActive,
		AgentID:   "agent-" + label,
		AnsName:   "ans://v1.0.0." + host,
		LogID:     "log-" + label,
		CreatedAt: "2025-01-01T00:00:00Z",
	}
	for _, m := range mut {
		m(&pe)
	}
	return pe
}

func display(name, desc string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.Entry.DisplayName = name; pe.Entry.Description = desc }
}
func tags(t ...string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.Entry.Tags = t }
}
func caps(c ...string) func(*project.ProjectedEntry) {
	return func(pe *project.ProjectedEntry) { pe.Entry.Capabilities = c }
}

// post issues a POST with a JSON body and returns status + parsed body.
func post(t *testing.T, srv *httptest.Server, path, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var parsed map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&parsed)
	return resp.StatusCode, parsed
}

func noLimit() *handler.RateLimiter { return handler.NewRateLimiter(0, 0) }

// ── Search happy path ────────────────────────────────────────────────

func TestSearch_OK(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 10}, noLimit(), nil)
	seed(t, idx, activeEntry("a.example.com", "flight", "application/mcp-server-card+json",
		"https://a.example.com/.well-known/mcp.json", display("Flight Booker", "books flights"),
		caps("Book Flight"), tags("travel")))

	status, body := post(t, srv, "/v1/search", `{"query":{"text":"flight"}}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, body %v", status, body)
	}
	results, _ := body["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results: %v", body["results"])
	}
	r0 := results[0].(map[string]any)
	if r0["identifier"] != "urn:ai:a.example.com:agents:flight" {
		t.Errorf("identifier: %v", r0["identifier"])
	}
	if r0["displayName"] != "Flight Booker" {
		t.Errorf("displayName: %v", r0["displayName"])
	}
	if r0["score"].(float64) != 100 {
		t.Errorf("score: %v", r0["score"])
	}
	if r0["source"] != sourceURL {
		t.Errorf("source: %v", r0["source"])
	}
	// Entry shape: type + url present, trustManifest nested.
	if r0["type"] != "application/mcp-server-card+json" {
		t.Errorf("type: %v", r0["type"])
	}
	if _, ok := r0["trustManifest"].(map[string]any); !ok {
		t.Errorf("trustManifest missing/shape: %v", r0["trustManifest"])
	}
}

// TestSearch_FilterBareScalar pins the frozen-spec Filter rule: "A bare
// scalar is accepted as a single-element array." A filter value given as
// a JSON string must behave identically to the one-element array form,
// and both must match the same entry.
func TestSearch_FilterBareScalar(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 10}, noLimit(), nil)
	seed(t, idx, activeEntry("a.example.com", "alpha", "application/mcp-server-card+json",
		"https://a.example.com/x", display("Alpha", "alpha"), tags("finance")))

	// Bare scalar form: "tags":"finance" (not an array).
	status, scalar := post(t, srv, "/v1/search",
		`{"query":{"text":"alpha","filter":{"tags":"finance"}}}`)
	if status != http.StatusOK {
		t.Fatalf("bare-scalar filter should be 200, got %d: %v", status, scalar)
	}
	if got := len(scalar["results"].([]any)); got != 1 {
		t.Fatalf("bare-scalar filter matched %d, want 1", got)
	}

	// Array form must produce the identical result.
	_, arr := post(t, srv, "/v1/search",
		`{"query":{"text":"alpha","filter":{"tags":["finance"]}}}`)
	if got := len(arr["results"].([]any)); got != 1 {
		t.Fatalf("array filter matched %d, want 1 (must match scalar form)", got)
	}

	// A non-matching bare scalar excludes the entry.
	_, none := post(t, srv, "/v1/search",
		`{"query":{"text":"alpha","filter":{"tags":"travel"}}}`)
	if got := len(none["results"].([]any)); got != 0 {
		t.Errorf("non-matching scalar filter should exclude, got %d", got)
	}
}

func TestSearch_FilterBareScalarRejectsNonString(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	// A number or object filter value is neither a string nor a string
	// array → 400 INVALID_ARGUMENT.
	for _, body := range []string{
		`{"query":{"text":"x","filter":{"tags":42}}}`,
		`{"query":{"text":"x","filter":{"tags":{"k":"v"}}}}`,
		`{"query":{"text":"x","filter":{"tags":[1,2]}}}`,
	} {
		status, parsed := post(t, srv, "/v1/search", body)
		if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
			t.Errorf("body %s: status=%d code=%v, want 400 INVALID_ARGUMENT", body, status, parsed["code"])
		}
	}
}

func TestSearch_EmptyResults(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	status, body := post(t, srv, "/v1/search", `{"query":{"text":"nothing"}}`)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	// results is required and must be present (possibly empty).
	if body["results"] == nil {
		t.Errorf("results key must be present even when empty: %v", body)
	}
	results, _ := body["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected empty results, got %v", results)
	}
}

// ── Search validation (400) ──────────────────────────────────────────

func TestSearch_Validation400(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"missing text":             `{"query":{}}`,
		"whitespace text":          `{"query":{"text":"   "}}`,
		"unsupported filter field": `{"query":{"text":"x","filter":{"bogus.field":["v"]}}}`,
		"empty filter values":      `{"query":{"text":"x","filter":{"tags":[]}}}`,
		"empty filter value":       `{"query":{"text":"x","filter":{"tags":[""]}}}`,
		"bad federation":           `{"query":{"text":"x"},"federation":"sideways"}`,
		"pageSize zero":            `{"query":{"text":"x"},"pageSize":0}`,
		"pageSize negative":        `{"query":{"text":"x"},"pageSize":-5}`,
		"malformed json":           `{not json`,
		"unknown field":            `{"query":{"text":"x"},"bogusTop":1}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
			status, parsed := post(t, srv, "/v1/search", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body=%v", status, parsed)
			}
			if parsed["code"] != "INVALID_ARGUMENT" {
				t.Errorf("code: %v, want INVALID_ARGUMENT", parsed["code"])
			}
		})
	}
}

func TestSearch_ProblemContentType(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	resp, err := http.Post(srv.URL+"/v1/search", "application/json", strings.NewReader(`{"query":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("content-type: %q, want application/problem+json", ct)
	}
}

// ── pageSize clamp ───────────────────────────────────────────────────

func TestSearch_PageSizeClampedToMax(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{MaxPageSize: 2, DefaultPageSize: 10}, noLimit(), nil)
	for _, l := range []string{"a", "b", "c", "d"} {
		seed(t, idx, activeEntry(l+".example.com", l, "application/mcp-server-card+json",
			"https://"+l+".example.com/x", display("Common", "common")))
	}
	// Ask for 100; MaxPageSize is 2, so only 2 come back and there's more.
	status, body := post(t, srv, "/v1/search", `{"query":{"text":"common"},"pageSize":100}`)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	results := body["results"].([]any)
	if len(results) != 2 {
		t.Errorf("pageSize not clamped to max: got %d, want 2", len(results))
	}
	if body["pageToken"] == nil {
		t.Errorf("expected pageToken when more results exist")
	}
}

// ── Pagination ───────────────────────────────────────────────────────

func TestSearch_PaginationViaToken(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 2}, noLimit(), nil)
	for _, l := range []string{"a", "b", "c"} {
		seed(t, idx, activeEntry(l+".example.com", l, "application/mcp-server-card+json",
			"https://"+l+".example.com/x", display("Common", "common")))
	}
	_, page1 := post(t, srv, "/v1/search", `{"query":{"text":"common"},"pageSize":2}`)
	tok, _ := page1["pageToken"].(string)
	if tok == "" {
		t.Fatal("no pageToken on page 1")
	}
	_, page2 := post(t, srv, "/v1/search", `{"query":{"text":"common"},"pageSize":2,"pageToken":"`+tok+`"}`)
	results := page2["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("page 2 should have the last result: got %d", len(results))
	}
	if page2["pageToken"] != nil {
		t.Errorf("page 2 should be the last page: %v", page2["pageToken"])
	}
}

func TestSearch_PageTokenBoundToQuery(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 1}, noLimit(), nil)
	for _, l := range []string{"a", "b"} {
		seed(t, idx, activeEntry(l+".example.com", l, "application/mcp-server-card+json",
			"https://"+l+".example.com/x", display("Common", "common")))
	}
	_, page1 := post(t, srv, "/v1/search", `{"query":{"text":"common"},"pageSize":1}`)
	tok := page1["pageToken"].(string)
	// Reuse the token against a DIFFERENT query text → rejected.
	status, parsed := post(t, srv, "/v1/search", `{"query":{"text":"different"},"pageSize":1,"pageToken":"`+tok+`"}`)
	if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("replaying a token across queries should 400: status=%d body=%v", status, parsed)
	}
}

func TestSearch_MalformedPageToken(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	status, parsed := post(t, srv, "/v1/search", `{"query":{"text":"x"},"pageToken":"!!!notbase64"}`)
	if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("malformed token should 400: status=%d body=%v", status, parsed)
	}
}

// ── Rate limiting ────────────────────────────────────────────────────

func TestSearch_RateLimited429(t *testing.T) {
	t.Parallel()
	// Burst 1, rate 0.0001/s (effectively no refill during the test).
	rl := handler.NewRateLimiter(0.0001, 1)
	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 10}, rl, nil)
	seed(t, idx, activeEntry("a.example.com", "a", "application/mcp-server-card+json",
		"https://a.example.com/x", display("Alpha", "alpha")))

	if status, _ := post(t, srv, "/v1/search", `{"query":{"text":"alpha"}}`); status != http.StatusOK {
		t.Fatalf("first request should pass: %d", status)
	}
	status, parsed := post(t, srv, "/v1/search", `{"query":{"text":"alpha"}}`)
	if status != http.StatusTooManyRequests {
		t.Fatalf("second request should be 429, got %d", status)
	}
	if parsed["code"] != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("code: %v", parsed["code"])
	}
}

// ── Explore ──────────────────────────────────────────────────────────

func TestExplore_OK(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{}, noLimit(), nil)
	seed(t, idx,
		activeEntry("a.example.com", "a", "application/mcp-server-card+json", "https://a.example.com/x"),
		activeEntry("b.example.com", "b", "application/a2a-agent-card+json", "https://b.example.com/y"),
		activeEntry("c.example.com", "c", "application/a2a-agent-card+json", "https://c.example.com/z"),
	)
	status, body := post(t, srv, "/v1/explore",
		`{"query":{},"resultType":{"facets":[{"field":"type","limit":20}]}}`)
	if status != http.StatusOK {
		t.Fatalf("status %d body %v", status, body)
	}
	if body["resultType"] != "facets" {
		t.Errorf("resultType: %v", body["resultType"])
	}
	facets := body["facets"].(map[string]any)
	typeFacet := facets["type"].(map[string]any)
	buckets := typeFacet["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("buckets: %v", buckets)
	}
	top := buckets[0].(map[string]any)
	if top["value"] != "application/a2a-agent-card+json" || top["count"].(float64) != 2 {
		t.Errorf("top bucket: %v", top)
	}
}

func TestExplore_Validation400(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no facets":           `{"query":{},"resultType":{"facets":[]}}`,
		"missing resultType":  `{"query":{}}`,
		"facet missing field": `{"query":{},"resultType":{"facets":[{"limit":5}]}}`,
		"unsupported facet":   `{"query":{},"resultType":{"facets":[{"field":"bogus"}]}}`,
		"facet limit zero":    `{"query":{},"resultType":{"facets":[{"field":"type","limit":0}]}}`,
		"facet negative min":  `{"query":{},"resultType":{"facets":[{"field":"type","minCount":-1}]}}`,
		"bad filter":          `{"query":{"filter":{"bogus":["v"]}},"resultType":{"facets":[{"field":"type"}]}}`,
		"malformed json":      `{not`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
			status, parsed := post(t, srv, "/v1/explore", body)
			if status != http.StatusBadRequest {
				t.Fatalf("status %d want 400; body=%v", status, parsed)
			}
			if parsed["code"] != "INVALID_ARGUMENT" {
				t.Errorf("code: %v", parsed["code"])
			}
		})
	}
}

// TestSearch_QueryBoundsCaps verifies the per-request cost caps reject
// oversized inputs with 400 INVALID_ARGUMENT (M5).
func TestSearch_QueryBoundsCaps(t *testing.T) {
	t.Parallel()
	bigText := strings.Repeat("a", 5000)                      // > 4 KiB
	manyTokens := strings.TrimSpace(strings.Repeat("t ", 70)) // > 64 tokens
	// > 100 filter values across one key.
	vals := make([]string, 0, 101)
	for i := range 101 {
		vals = append(vals, `"v`+strconv.Itoa(i)+`"`)
	}
	bigFilter := `{"query":{"text":"x","filter":{"tags":[` + strings.Join(vals, ",") + `]}}}`

	cases := map[string]string{
		"text over byte cap":    `{"query":{"text":"` + bigText + `"}}`,
		"text over token cap":   `{"query":{"text":"` + manyTokens + `"}}`,
		"filter over value cap": bigFilter,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
			status, parsed := post(t, srv, "/v1/search", body)
			if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
				t.Fatalf("%s: status=%d code=%v, want 400 INVALID_ARGUMENT", name, status, parsed["code"])
			}
		})
	}
}

// TestSearch_RejectsControlCharsInText verifies L13: control/format runes
// in query.text are rejected with 400, not passed to FTS5 (where they'd
// surface as a 500).
func TestSearch_RejectsControlCharsInText(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	// JSON \uXXXX escapes decode to the control/format runes when the
	// server parses the body, so the Go source stays plain ASCII.
	cases := map[string]string{
		"NUL":          `{"query":{"text":"flight\u0000booking"}}`,
		"ESC":          `{"query":{"text":"flight\u001bbooking"}}`,
		"RLO override": `{"query":{"text":"flight\u202ebooking"}}`,
		"zero-width":   `{"query":{"text":"flight\u200bbooking"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, parsed := post(t, srv, "/v1/search", body)
			if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
				t.Errorf("%s: status=%d code=%v, want 400 INVALID_ARGUMENT", name, status, parsed["code"])
			}
		})
	}
}

func TestSearch_RateLimitedSetsRetryAfter(t *testing.T) {
	t.Parallel()
	rl := handler.NewRateLimiter(0.0001, 1)
	srv, _ := testServer(t, handler.Config{}, rl, nil)
	_, _ = post(t, srv, "/v1/search", `{"query":{"text":"x"}}`)
	resp, err := http.Post(srv.URL+"/v1/search", "application/json", strings.NewReader(`{"query":{"text":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 response must carry a Retry-After header")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("response must carry X-Content-Type-Options: nosniff")
	}
}

func TestExplore_FacetCaps(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"too many facets": `{"query":{},"resultType":{"facets":[` +
			`{"field":"type"},{"field":"tags"},{"field":"capabilities"},` +
			`{"field":"publisher"},{"field":"trustManifest.attestations.type"},` +
			`{"field":"type"}]}}`, // 6 entries → over the cap of 5
		"duplicate facet field": `{"query":{},"resultType":{"facets":[{"field":"type"},{"field":"type"}]}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
			status, parsed := post(t, srv, "/v1/explore", body)
			if status != http.StatusBadRequest || parsed["code"] != "INVALID_ARGUMENT" {
				t.Fatalf("%s: status=%d code=%v, want 400 INVALID_ARGUMENT", name, status, parsed["code"])
			}
		})
	}
}

func TestExplore_RateLimited(t *testing.T) {
	t.Parallel()
	rl := handler.NewRateLimiter(0.0001, 1)
	srv, _ := testServer(t, handler.Config{}, rl, nil)
	_, _ = post(t, srv, "/v1/explore", `{"query":{},"resultType":{"facets":[{"field":"type"}]}}`)
	status, parsed := post(t, srv, "/v1/explore", `{"query":{},"resultType":{"facets":[{"field":"type"}]}}`)
	if status != http.StatusTooManyRequests || parsed["code"] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("second explore should be 429: status=%d body=%v", status, parsed)
	}
}

// ── Federation referrals ─────────────────────────────────────────────

func TestSearch_ReferralsMode(t *testing.T) {
	t.Parallel()
	referral := project.Entry{
		Identifier:  "urn:ai:other.example.org:agents:registry",
		DisplayName: "Other Registry",
		Type:        "application/ai-registry+json",
		URL:         "https://other.example.org/v1/",
	}
	srv, idx := testServer(t, handler.Config{
		MaxPageSize: 100, DefaultPageSize: 10, Referrals: []project.Entry{referral},
	}, noLimit(), nil)
	seed(t, idx, activeEntry("a.example.com", "a", "application/mcp-server-card+json",
		"https://a.example.com/x", display("Alpha", "alpha")))

	_, body := post(t, srv, "/v1/search", `{"query":{"text":"alpha"},"federation":"referrals"}`)
	refs, ok := body["referrals"].([]any)
	if !ok || len(refs) != 1 {
		t.Fatalf("expected 1 referral in referrals mode: %v", body["referrals"])
	}

	// auto mode omits referrals.
	_, autoBody := post(t, srv, "/v1/search", `{"query":{"text":"alpha"},"federation":"auto"}`)
	if autoBody["referrals"] != nil {
		t.Errorf("auto mode should not return referrals: %v", autoBody["referrals"])
	}
}

// ── Staleness ────────────────────────────────────────────────────────

func TestSearch_StaleSinceWhenBehind(t *testing.T) {
	t.Parallel()
	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	// now is 10 minutes after the last poll; bound is 1 minute → stale.
	now := func() time.Time { return pollAt.Add(10 * time.Minute) }
	srv, idx := testServer(t, handler.Config{
		MaxPageSize: 100, DefaultPageSize: 10, StaleBound: time.Minute,
	}, noLimit(), now)
	if err := idx.SaveCursor(context.Background(), index.Cursor{LastLogID: "x", LastPollOK: pollAt}); err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	_, body := post(t, srv, "/v1/search", `{"query":{"text":"anything"}}`)
	if body["staleSince"] != "2025-06-01T12:00:00Z" {
		t.Errorf("staleSince: %v, want the last poll time", body["staleSince"])
	}
}

func TestSearch_NoStaleSinceWhenFresh(t *testing.T) {
	t.Parallel()
	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return pollAt.Add(10 * time.Second) } // within 1m bound
	srv, idx := testServer(t, handler.Config{
		MaxPageSize: 100, DefaultPageSize: 10, StaleBound: time.Minute,
	}, noLimit(), now)
	_ = idx.SaveCursor(context.Background(), index.Cursor{LastPollOK: pollAt})
	_, body := post(t, srv, "/v1/search", `{"query":{"text":"x"}}`)
	if _, present := body["staleSince"]; present {
		t.Errorf("fresh index should omit staleSince: %v", body["staleSince"])
	}
}

func TestExplore_StaleSincePropagates(t *testing.T) {
	t.Parallel()
	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return pollAt.Add(time.Hour) }
	srv, idx := testServer(t, handler.Config{StaleBound: time.Minute}, noLimit(), now)
	_ = idx.SaveCursor(context.Background(), index.Cursor{LastPollOK: pollAt})
	_, body := post(t, srv, "/v1/explore", `{"query":{},"resultType":{"facets":[{"field":"type"}]}}`)
	if body["staleSince"] != "2025-06-01T12:00:00Z" {
		t.Errorf("explore staleSince: %v", body["staleSince"])
	}
}

// ── Operator routes ──────────────────────────────────────────────────

func TestHealth_AlwaysOK(t *testing.T) {
	t.Parallel()
	// Health is liveness — 200 even on a never-polled (empty) index.
	srv, _ := testServer(t, handler.Config{}, noLimit(), nil)
	resp, err := http.Get(srv.URL + "/v1/admin/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health status %d, want 200", resp.StatusCode)
	}
}

func TestReady_GatedOnFirstPoll(t *testing.T) {
	t.Parallel()
	srv, idx := testServer(t, handler.Config{}, noLimit(), nil)

	// Before any poll: readiness is 503 (M8) — a never-bootstrapped
	// replica must not be routed discovery traffic.
	resp, err := http.Get(srv.URL + "/v1/admin/ready")
	if err != nil {
		t.Fatalf("get ready: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("never-polled ready status %d, want 503", resp.StatusCode)
	}

	// After a successful poll (cursor's LastPollOK set): ready flips to 200.
	if err := idx.SaveCursor(context.Background(), index.Cursor{LastPollOK: time.Now()}); err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	resp2, err := http.Get(srv.URL + "/v1/admin/ready")
	if err != nil {
		t.Fatalf("get ready: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("ready after poll status %d, want 200", resp2.StatusCode)
	}
}
