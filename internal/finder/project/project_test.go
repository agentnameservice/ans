package project_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/finder/feed"
	"github.com/godaddy/ans/internal/finder/project"
)

// defaultOpts is the projection config used by golden and most table
// tests: a real TL base URL and https-only.
var defaultOpts = project.Options{
	TLBaseURL: "https://tl.ans.example.org",
	AllowHTTP: false,
}

// goldenView is a TEST-LOCAL serialization of a Projection that captures
// BOTH the wire Entry and the wrapper bookkeeping fields
// (Lifecycle/AgentID/AnsName/LogID/ExpiresAt) plus the Skips. The wire
// Entry alone cannot pin tombstone behavior — tombstones carry their
// meaning entirely in the wrapper — so the golden compares this fuller
// view. Field tags are explicit and stable so the golden bytes are
// deterministic.
type goldenView struct {
	Entries []goldenEntry `json:"entries"`
	Skipped []goldenSkip  `json:"skipped"`
}

type goldenEntry struct {
	Lifecycle string `json:"lifecycle"`
	AgentID   string `json:"agentId"`
	AnsName   string `json:"ansName"`
	LogID     string `json:"logId"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	// Entry is the wire shape, marshaled exactly as it would appear on
	// the discovery API.
	Entry project.Entry `json:"entry"`
}

type goldenSkip struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

func toGoldenView(p project.Projection) goldenView {
	gv := goldenView{
		Entries: make([]goldenEntry, 0, len(p.Entries)),
		Skipped: make([]goldenSkip, 0, len(p.Skipped)),
	}
	for _, pe := range p.Entries {
		gv.Entries = append(gv.Entries, goldenEntry{
			Lifecycle: string(pe.Lifecycle),
			AgentID:   pe.AgentID,
			AnsName:   pe.AnsName,
			LogID:     pe.LogID,
			CreatedAt: pe.CreatedAt,
			ExpiresAt: pe.ExpiresAt,
			Entry:     pe.Entry,
		})
	}
	for _, s := range p.Skipped {
		gv.Skipped = append(gv.Skipped, goldenSkip{Kind: string(s.Kind), Detail: s.Detail})
	}
	return gv
}

// goldenCases maps a fixture file to its golden output file. Each
// fixture is loaded, projected with defaultOpts, and the goldenView is
// byte-compared against testdata/<name>.golden.json. Regenerate with
// `UPDATE_GOLDEN=1 go test ./internal/finder/project/`.
var goldenCases = map[string]struct {
	fixture string
	golden  string
}{
	"registered":      {"testdata/event_registered.json", "testdata/event_registered.golden.json"},
	"revoked":         {"testdata/event_revoked.json", "testdata/event_revoked.golden.json"},
	"revoked_minimal": {"testdata/event_revoked_minimal.json", "testdata/event_revoked_minimal.golden.json"},
	"renewed":         {"testdata/event_renewed.json", "testdata/event_renewed.golden.json"},
	"deprecated":      {"testdata/event_deprecated.json", "testdata/event_deprecated.golden.json"},
	"no_endpoints":    {"testdata/event_no_endpoints.json", "testdata/event_no_endpoints.golden.json"},
	"no_displayname":  {"testdata/event_no_displayname.json", "testdata/event_no_displayname.golden.json"},
	"adversarial":     {"testdata/event_adversarial_text.json", "testdata/event_adversarial_text.golden.json"},
	"nonz_offset":     {"testdata/event_nonz_offset.json", "testdata/event_nonz_offset.golden.json"},
}

func TestFromEvent_Golden(t *testing.T) {
	t.Parallel()
	for name, tc := range goldenCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := loadFixture(t, tc.fixture)
			proj, err := project.FromEvent(item, defaultOpts)
			if err != nil {
				t.Fatalf("FromEvent(%s): %v", tc.fixture, err)
			}
			got := mustMarshalIndent(t, toGoldenView(proj))

			if *update {
				mustWrite(t, tc.golden, got)
				return
			}
			want := mustRead(t, tc.golden)
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch for %s:\n  got:\n%s\n  want:\n%s", name, got, want)
			}
		})
	}
}

// ── Lifecycle split: tombstones ──────────────────────────────────

func TestFromEvent_Tombstones(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		fixture     string
		wantLC      project.Lifecycle
		wantID      bool // identifier present (label minted)
		wantAgent   string
		wantLog     string
		wantCreated string // CreatedAt expected on wrapper (verbatim)
		wantTS      string // ExpiresAt expected on wrapper
	}{
		"revoked with display": {
			fixture: "testdata/event_revoked.json", wantLC: project.LifecycleRevoked,
			wantID: true, wantAgent: "550e8400-e29b-41d4-a716-446655440000",
			wantLog:     "019a7a99-1111-7b5b-b048-d0b78f4b4c5f",
			wantCreated: "2025-03-10T09:00:00Z", wantTS: "2026-01-08T12:30:00Z",
		},
		"revoked minimal (no display)": {
			fixture: "testdata/event_revoked_minimal.json", wantLC: project.LifecycleRevoked,
			wantID: false, wantAgent: "660e8400-e29b-41d4-a716-446655440111",
			wantLog:     "019a7aaa-2222-7b5b-b048-d0b78f4b4c5f",
			wantCreated: "2025-03-11T10:15:30Z", wantTS: "",
		},
		"deprecated": {
			fixture: "testdata/event_deprecated.json", wantLC: project.LifecycleDeprecated,
			wantID: true, wantAgent: "770e8400-e29b-41d4-a716-446655440222",
			wantLog:     "019a7acc-4444-7b5b-b048-d0b78f4b4c5f",
			wantCreated: "2025-07-15T18:45:00Z", wantTS: "2026-06-01T00:00:00Z",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := loadFixture(t, tc.fixture)
			proj, err := project.FromEvent(item, defaultOpts)
			if err != nil {
				t.Fatalf("FromEvent: %v", err)
			}
			if len(proj.Entries) != 1 {
				t.Fatalf("expected exactly 1 tombstone entry, got %d", len(proj.Entries))
			}
			if len(proj.Skipped) != 0 {
				t.Fatalf("tombstone should produce no skips, got %v", proj.Skipped)
			}
			e := proj.Entries[0]
			if e.Lifecycle != tc.wantLC {
				t.Errorf("lifecycle: got %q, want %q", e.Lifecycle, tc.wantLC)
			}
			if e.AgentID != tc.wantAgent {
				t.Errorf("agentId: got %q, want %q", e.AgentID, tc.wantAgent)
			}
			if e.LogID != tc.wantLog {
				t.Errorf("logId: got %q, want %q", e.LogID, tc.wantLog)
			}
			// Tombstone timestamp = createdAt verbatim (the index orders
			// suppression by it, so it MUST be carried), and ExpiresAt
			// passes through too. Both asserted directly here.
			if e.CreatedAt != tc.wantCreated {
				t.Errorf("createdAt: got %q, want %q", e.CreatedAt, tc.wantCreated)
			}
			if e.ExpiresAt != tc.wantTS {
				t.Errorf("expiresAt: got %q, want %q", e.ExpiresAt, tc.wantTS)
			}
			// Tombstone wire Entry carries NO url/data/display metadata,
			// no trust manifest.
			if e.URL != "" || e.Data != nil {
				t.Errorf("tombstone Entry must carry neither url nor data: url=%q data=%v", e.URL, e.Data)
			}
			if e.DisplayName != "" || e.Description != "" || e.Type != "" {
				t.Errorf("tombstone Entry must carry no display metadata: %+v", e.Entry)
			}
			if e.TrustManifest != nil {
				t.Errorf("tombstone Entry must carry no trust manifest")
			}
			if e.Capabilities != nil || e.Tags != nil || e.Metadata != nil {
				t.Errorf("tombstone Entry must carry no lists/metadata")
			}
			if tc.wantID && e.Identifier == "" {
				t.Errorf("expected best-effort identifier, got empty")
			}
			if !tc.wantID && e.Identifier != "" {
				t.Errorf("expected no identifier (no label), got %q", e.Identifier)
			}
		})
	}
}

// TestFromEvent_TombstoneIgnoresBadDisplay proves a REVOKED event whose
// display name is adversarial/unmintable still tombstones — the safety
// rule. The tombstone path never touches label minting as a gate.
func TestFromEvent_TombstoneIgnoresBadDisplay(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_revoked_minimal.json")
	item.AgentDisplayName = "\u200b\u202e" // sanitizes to empty -> no URN label
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	if len(proj.Entries) != 1 || proj.Entries[0].Lifecycle != project.LifecycleRevoked {
		t.Fatalf("revocation must still tombstone despite unmintable display: %+v", proj)
	}
	if proj.Entries[0].Identifier != "" {
		t.Errorf("unmintable label should leave identifier empty, got %q", proj.Entries[0].Identifier)
	}
}

// TestFromEvent_TombstoneMissingActiveOnlyField is the inverse of
// event_revoked_minimal: a REVOKED/DEPRECATED event missing a field that
// only the Active path requires (version) MUST still tombstone. Before
// the validation split this returned an error and dropped the
// revocation entirely — the exact fail-open the lifecycle split exists
// to prevent.
func TestFromEvent_TombstoneMissingActiveOnlyField(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		eventType string
		wantLC    project.Lifecycle
	}{
		"revoked missing version":    {feed.EventTypeAgentRevoked, project.LifecycleRevoked},
		"deprecated missing version": {feed.EventTypeAgentDeprecated, project.LifecycleDeprecated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := loadFixture(t, "testdata/event_revoked.json")
			item.EventType = tc.eventType
			item.Version = "" // Active-only required field, absent
			proj, err := project.FromEvent(item, defaultOpts)
			if err != nil {
				t.Fatalf("missing version must NOT error for a tombstone: %v", err)
			}
			if len(proj.Entries) != 1 || proj.Entries[0].Lifecycle != tc.wantLC {
				t.Fatalf("expected one %s tombstone, got %+v", tc.wantLC, proj)
			}
			if proj.Entries[0].AgentID == "" || proj.Entries[0].LogID == "" {
				t.Errorf("tombstone wrapper keys missing: %+v", proj.Entries[0])
			}
		})
	}
}

// TestFromEvent_ActiveMissingVersionErrors confirms the other half of
// the split: an Active event missing version still fails (the full
// contract runs only on the Active path).
func TestFromEvent_ActiveMissingVersionErrors(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_registered.json")
	item.Version = ""
	if _, err := project.FromEvent(item, defaultOpts); err == nil {
		t.Fatal("Active event missing version must error")
	}
}

// ── Active path: fan-out and exclusions ──────────────────────────

func TestFromEvent_ActiveFanOut(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_registered.json")
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	// 3 endpoints: A2A + MCP → 2 entries; HTTP-API → no entry, no skip.
	if len(proj.Entries) != 2 {
		t.Fatalf("expected 2 entries (A2A+MCP), got %d: %+v", len(proj.Entries), proj.Entries)
	}
	if len(proj.Skipped) != 0 {
		t.Fatalf("HTTP-API exclusion is not a skip; got skips %v", proj.Skipped)
	}
	gotTypes := []string{proj.Entries[0].Type, proj.Entries[1].Type}
	// Sorted by (identifier, type, url); both share identifier, so type
	// orders them: a2a-agent-card < mcp-server.
	want := []string{"application/a2a-agent-card+json", "application/mcp-server+json"}
	for i := range want {
		if gotTypes[i] != want[i] {
			t.Errorf("entry %d type: got %q, want %q", i, gotTypes[i], want[i])
		}
	}
	for _, e := range proj.Entries {
		if e.Lifecycle != project.LifecycleActive {
			t.Errorf("active entry lifecycle: got %q", e.Lifecycle)
		}
	}
}

func TestFromEvent_NoEndpoints(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_no_endpoints.json")
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	// displayName present (label mints) but no endpoints → empty
	// projection, no skip, no error.
	if len(proj.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(proj.Entries))
	}
	if len(proj.Skipped) != 0 {
		t.Fatalf("expected no skips, got %v", proj.Skipped)
	}
}

func TestFromEvent_NoDisplayName(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_no_displayname.json")
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	// endpoints present but no display name → no URN label → one
	// event-level Skip, no entries.
	if len(proj.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(proj.Entries))
	}
	if len(proj.Skipped) != 1 || proj.Skipped[0].Kind != project.SkipMissingLabel {
		t.Fatalf("expected one MissingLabel skip, got %v", proj.Skipped)
	}
}

// ── Unknown eventType → Skip, never error ────────────────────────

func TestFromEvent_UnknownEventType(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_registered.json")
	item.EventType = "AGENT_TELEPORTED"
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("unknown eventType must NOT error (would wedge ingestion): %v", err)
	}
	if len(proj.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(proj.Entries))
	}
	if len(proj.Skipped) != 1 || proj.Skipped[0].Kind != project.SkipUnknownEventType {
		t.Fatalf("expected one UnknownEventType skip, got %v", proj.Skipped)
	}
}

// ── feed.Validate failures → error ───────────────────────────────

func TestFromEvent_ValidateFailureIsError(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*feed.EventItem){
		"missing logId":   func(e *feed.EventItem) { e.LogID = "" },
		"bad agentId":     func(e *feed.EventItem) { e.AgentID = "nope" },
		"bad createdAt":   func(e *feed.EventItem) { e.CreatedAt = "whenever" },
		"host mismatch":   func(e *feed.EventItem) { e.AgentHost = "other.example.com" },
		"unparseable ans": func(e *feed.EventItem) { e.AnsName = "not-an-ans-name" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := loadFixture(t, "testdata/event_registered.json")
			mutate(&item)
			proj, err := project.FromEvent(item, defaultOpts)
			if err == nil {
				t.Fatalf("%s: expected error", name)
			}
			if len(proj.Entries) != 0 || len(proj.Skipped) != 0 {
				t.Fatalf("%s: error path must return empty projection, got %+v", name, proj)
			}
		})
	}
}

// ── URL policy table ─────────────────────────────────────────────

func TestFromEvent_URLPolicy(t *testing.T) {
	t.Parallel()
	type want struct {
		entries int
		skips   int
		skip0   project.SkipKind
		entURL  string // expected entry URL when entries==1
	}
	base := func() feed.EventItem {
		// single MCP endpoint, mintable label
		return feed.EventItem{
			LogID:            "019a7b11-9999-7b5b-b048-d0b78f4b4c5f",
			EventType:        feed.EventTypeAgentRegistered,
			CreatedAt:        "2025-05-01T00:00:00Z",
			AgentID:          "cc0e8400-e29b-41d4-a716-446655440777",
			AnsName:          "ans://v1.0.0.host.example.com",
			AgentHost:        "host.example.com",
			AgentDisplayName: "Policy Agent",
			Version:          "1.0.0",
			Endpoints: []feed.AgentEndpoint{{
				AgentURL: "https://host.example.com/mcp",
				Protocol: feed.ProtocolMCP,
			}},
		}
	}
	cases := map[string]struct {
		opts   project.Options
		mutate func(*feed.EventItem)
		want   want
	}{
		"metaDataUrl absent → well-known fallback used": {
			opts:   defaultOpts,
			mutate: func(e *feed.EventItem) {},
			want:   want{entries: 1, entURL: "https://host.example.com/.well-known/mcp.json"},
		},
		"valid metaDataUrl used verbatim": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/custom/meta.json"
			},
			want: want{entries: 1, entURL: "https://host.example.com/custom/meta.json"},
		},
		"metaDataUrl wrong scheme → Skip fail-closed (no fallback)": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "ftp://host.example.com/meta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl http but AllowHTTP off → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "http://host.example.com/meta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl http with AllowHTTP on → used": {
			opts: project.Options{TLBaseURL: "https://tl.ans.example.org", AllowHTTP: true},
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "http://host.example.com/meta.json"
			},
			want: want{entries: 1, entURL: "http://host.example.com/meta.json"},
		},
		"metaDataUrl host mismatch → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://evil.example.net/meta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with userinfo → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://user:pass@host.example.com/meta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with query → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/meta.json?x=1"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with fragment → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/meta.json#frag"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl relative (not absolute) → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "/meta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl non-default port allowed (host matches)": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com:8443/meta.json"
			},
			want: want{entries: 1, entURL: "https://host.example.com:8443/meta.json"},
		},
		"metaDataUrl unparseable → Skip": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/%zz"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with bidi rune → Skip fail-closed": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				// RLO inside the path — must be rejected, not stripped:
				// stripping could silently change the effective path.
				e.Endpoints[0].MetaDataURL = "https://host.example.com/\u202emeta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with zero-width rune → Skip fail-closed": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/me\u200bta.json"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
		"metaDataUrl with bare trailing ? → Skip (ForceQuery)": {
			opts: defaultOpts,
			mutate: func(e *feed.EventItem) {
				e.Endpoints[0].MetaDataURL = "https://host.example.com/meta.json?"
			},
			want: want{entries: 0, skips: 1, skip0: project.SkipInvalidURL},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := base()
			tc.mutate(&item)
			proj, err := project.FromEvent(item, tc.opts)
			if err != nil {
				t.Fatalf("FromEvent: %v", err)
			}
			if len(proj.Entries) != tc.want.entries {
				t.Fatalf("entries: got %d, want %d (%+v)", len(proj.Entries), tc.want.entries, proj)
			}
			if len(proj.Skipped) != tc.want.skips {
				t.Fatalf("skips: got %d, want %d (%v)", len(proj.Skipped), tc.want.skips, proj.Skipped)
			}
			if tc.want.skips > 0 && proj.Skipped[0].Kind != tc.want.skip0 {
				t.Errorf("skip kind: got %q, want %q", proj.Skipped[0].Kind, tc.want.skip0)
			}
			if tc.want.entries == 1 && proj.Entries[0].URL != tc.want.entURL {
				t.Errorf("entry URL: got %q, want %q", proj.Entries[0].URL, tc.want.entURL)
			}
		})
	}
}

// TestFromEvent_AgentURLMetadata covers the metadata.agentUrl rule:
// present-and-valid → included; present-but-invalid → omitted (entry
// survives, NOT a skip).
func TestFromEvent_AgentURLMetadata(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		agentURL    string
		wantPresent bool
	}{
		"valid agentUrl included":   {"https://host.example.com/mcp", true},
		"mismatch agentUrl omitted": {"https://evil.example.net/mcp", false},
		"http agentUrl omitted":     {"http://host.example.com/mcp", false},
		"empty agentUrl omitted":    {"", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			item := feed.EventItem{
				LogID:            "019a7b22-aaaa-7b5b-b048-d0b78f4b4c5f",
				EventType:        feed.EventTypeAgentRegistered,
				CreatedAt:        "2025-05-02T00:00:00Z",
				AgentID:          "dd0e8400-e29b-41d4-a716-446655440888",
				AnsName:          "ans://v1.0.0.host.example.com",
				AgentHost:        "host.example.com",
				AgentDisplayName: "Meta Agent",
				Version:          "1.0.0",
				Endpoints: []feed.AgentEndpoint{{
					AgentURL:    tc.agentURL,
					MetaDataURL: "https://host.example.com/.well-known/mcp.json",
					Protocol:    feed.ProtocolMCP,
				}},
			}
			proj, err := project.FromEvent(item, defaultOpts)
			if err != nil {
				t.Fatalf("FromEvent: %v", err)
			}
			if len(proj.Entries) != 1 {
				t.Fatalf("expected 1 entry (agentUrl invalidity must not drop entry), got %d: %+v", len(proj.Entries), proj)
			}
			_, present := proj.Entries[0].Metadata["agentUrl"]
			if present != tc.wantPresent {
				t.Errorf("agentUrl present: got %v, want %v (metadata=%v)", present, tc.wantPresent, proj.Entries[0].Metadata)
			}
			// ansName and logId always present.
			md := proj.Entries[0].Metadata
			if md["ansName"] != "ans://v1.0.0.host.example.com" || md["logId"] == "" {
				t.Errorf("metadata missing ansName/logId: %v", md)
			}
		})
	}
}

// ── Unknown protocol → per-endpoint Skip ─────────────────────────

func TestFromEvent_UnknownProtocol(t *testing.T) {
	t.Parallel()
	item := feed.EventItem{
		LogID:            "019a7b33-bbbb-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-05-03T00:00:00Z",
		AgentID:          "ee0e8400-e29b-41d4-a716-446655440999",
		AnsName:          "ans://v1.0.0.host.example.com",
		AgentHost:        "host.example.com",
		AgentDisplayName: "Multi Agent",
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{
			{AgentURL: "https://host.example.com/mcp", Protocol: feed.ProtocolMCP},
			{AgentURL: "https://host.example.com/x", Protocol: "QUANTUM"},
		},
	}
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	if len(proj.Entries) != 1 {
		t.Fatalf("expected 1 entry (MCP survives), got %d", len(proj.Entries))
	}
	if len(proj.Skipped) != 1 || proj.Skipped[0].Kind != project.SkipUnknownProtocol {
		t.Fatalf("expected one UnknownProtocol skip, got %v", proj.Skipped)
	}
}

// TestFromEvent_DuplicateProtocolSortsByURL proves two endpoints of the
// same protocol (contract-legal) both project, share identifier and
// type, and order deterministically by url.
func TestFromEvent_DuplicateProtocolSortsByURL(t *testing.T) {
	t.Parallel()
	item := feed.EventItem{
		LogID:            "019a7b88-1010-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-05-08T00:00:00Z",
		AgentID:          "440e8400-e29b-41d4-a716-446655440eee",
		AnsName:          "ans://v1.0.0.host.example.com",
		AgentHost:        "host.example.com",
		AgentDisplayName: "Dual MCP",
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{
			{AgentURL: "https://host.example.com/mcp-b", MetaDataURL: "https://host.example.com/z-meta.json", Protocol: feed.ProtocolMCP},
			{AgentURL: "https://host.example.com/mcp-a", MetaDataURL: "https://host.example.com/a-meta.json", Protocol: feed.ProtocolMCP},
		},
	}
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	if len(proj.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(proj.Entries))
	}
	// Same identifier + same type → url breaks the tie, ascending.
	if proj.Entries[0].Identifier != proj.Entries[1].Identifier {
		t.Errorf("duplicate protocol entries must share identifier")
	}
	if proj.Entries[0].URL != "https://host.example.com/a-meta.json" {
		t.Errorf("entries not sorted by url: %q first", proj.Entries[0].URL)
	}
	if proj.Entries[1].URL != "https://host.example.com/z-meta.json" {
		t.Errorf("second entry url: %q", proj.Entries[1].URL)
	}
}

// ── URN lineage table ────────────────────────────────────────────

func TestFromEvent_URNLineage(t *testing.T) {
	t.Parallel()
	mk := func(host, ans, display, ver string) feed.EventItem {
		return feed.EventItem{
			LogID:            "019a7b44-cccc-7b5b-b048-d0b78f4b4c5f",
			EventType:        feed.EventTypeAgentRegistered,
			CreatedAt:        "2025-05-04T00:00:00Z",
			AgentID:          "ff0e8400-e29b-41d4-a716-446655440aaa",
			AnsName:          ans,
			AgentHost:        host,
			AgentDisplayName: display,
			Version:          ver,
			Endpoints: []feed.AgentEndpoint{{
				AgentURL: "https://" + host + "/mcp",
				Protocol: feed.ProtocolMCP,
			}},
		}
	}
	v1 := mk("host.example.com", "ans://v1.0.0.host.example.com", "Flight Booker", "1.0.0")
	v2 := mk("host.example.com", "ans://v2.0.0.host.example.com", "Flight Booker", "2.0.0")
	other := mk("host.example.com", "ans://v1.0.0.host.example.com", "Hotel Finder", "1.0.0")

	p1, _ := project.FromEvent(v1, defaultOpts)
	p2, _ := project.FromEvent(v2, defaultOpts)
	po, _ := project.FromEvent(other, defaultOpts)

	id1 := p1.Entries[0].Identifier
	id2 := p2.Entries[0].Identifier
	ido := po.Entries[0].Identifier

	// Same host + same display name → SAME URN across versions (lineage
	// handle), but versions differ on the entry's version field.
	if id1 != id2 {
		t.Errorf("two versions of same agent must share URN: %q vs %q", id1, id2)
	}
	if p1.Entries[0].Version == p2.Entries[0].Version {
		t.Errorf("versions must differ: both %q", p1.Entries[0].Version)
	}
	// Distinct display name → distinct label.
	if id1 == ido {
		t.Errorf("distinct agents must have distinct URNs: %q == %q", id1, ido)
	}
	if want := "urn:ai:host.example.com:agents:Flight-Booker"; id1 != want {
		t.Errorf("URN: got %q, want %q", id1, want)
	}
}

// ── Adversarial text hygiene ─────────────────────────────────────

func TestFromEvent_AdversarialText(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_adversarial_text.json")
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	if len(proj.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(proj.Entries), proj)
	}
	e := proj.Entries[0]
	// Every emitted string must be free of Cc and bidi/zero-width Cf.
	check := func(label, s string) {
		for _, r := range s {
			if r == 0x1b || r == 0x00 || r == 0x202e || r == 0x200b ||
				r == 0x2066 || r == 0x2069 {
				t.Errorf("%s still contains disallowed rune U+%04X: %q", label, r, s)
			}
		}
	}
	check("displayName", e.DisplayName)
	check("description", e.Description)
	check("version", e.Version)
	check("identifier", e.Identifier)
	for _, c := range e.Capabilities {
		check("capability", c)
	}
	for _, tg := range e.Tags {
		check("tag", tg)
	}
	// f2's name was only ZWSP+RLO → sanitizes to empty → dropped before
	// dedup, so it never occupies a capability slot. Only "CleanTool"
	// survives.
	if len(e.Capabilities) != 1 || e.Capabilities[0] != "CleanTool" {
		t.Errorf("capabilities: got %v, want [CleanTool]", e.Capabilities)
	}
	// version had a trailing ZWSP stripped.
	if e.Version != "1.0.0" {
		t.Errorf("version: got %q, want 1.0.0", e.Version)
	}
}

// ── dedup / sort / cap ───────────────────────────────────────────

func TestFromEvent_DedupSortCap(t *testing.T) {
	t.Parallel()
	fns := make([]feed.AgentFunction, 0, 60)
	// 60 distinct names → capped to 50 capabilities; duplicate "Zeta"
	// collapses; an empty-after-sanitize name is dropped before dedup.
	fns = append(fns, feed.AgentFunction{ID: "z1", Name: "Zeta", Tags: []string{"t", "t", "u"}})
	fns = append(fns, feed.AgentFunction{ID: "z2", Name: "Zeta", Tags: []string{"u", "v"}})
	fns = append(fns, feed.AgentFunction{ID: "e", Name: "\u200b", Tags: []string{"\u202e"}})
	for i := range 60 {
		fns = append(fns, feed.AgentFunction{ID: "f", Name: capName(i)})
	}
	item := feed.EventItem{
		LogID:            "019a7b55-dddd-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-05-05T00:00:00Z",
		AgentID:          "110e8400-e29b-41d4-a716-446655440bbb",
		AnsName:          "ans://v1.0.0.host.example.com",
		AgentHost:        "host.example.com",
		AgentDisplayName: "Cap Agent",
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{{
			AgentURL:  "https://host.example.com/mcp",
			Protocol:  feed.ProtocolMCP,
			Functions: fns,
		}},
	}
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	e := proj.Entries[0]
	if len(e.Capabilities) != 50 {
		t.Errorf("capabilities cap: got %d, want 50", len(e.Capabilities))
	}
	// sorted ascending
	for i := 1; i < len(e.Capabilities); i++ {
		if e.Capabilities[i-1] > e.Capabilities[i] {
			t.Fatalf("capabilities not sorted at %d: %q > %q", i, e.Capabilities[i-1], e.Capabilities[i])
		}
	}
	// "" (sanitized empty) must not appear.
	for _, c := range e.Capabilities {
		if c == "" {
			t.Fatal("empty capability leaked into output")
		}
	}
	// tags deduped: t,u,v → 3 unique, sorted.
	wantTags := []string{"t", "u", "v"}
	if strings.Join(e.Tags, ",") != strings.Join(wantTags, ",") {
		t.Errorf("tags: got %v, want %v", e.Tags, wantTags)
	}
}

func TestFromEvent_TagsCap(t *testing.T) {
	t.Parallel()
	tags := make([]string, 0, 25)
	for i := range 25 {
		tags = append(tags, capName(i))
	}
	item := feed.EventItem{
		LogID:            "019a7b66-eeee-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-05-06T00:00:00Z",
		AgentID:          "220e8400-e29b-41d4-a716-446655440ccc",
		AnsName:          "ans://v1.0.0.host.example.com",
		AgentHost:        "host.example.com",
		AgentDisplayName: "Tag Agent",
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{{
			AgentURL:  "https://host.example.com/mcp",
			Protocol:  feed.ProtocolMCP,
			Functions: []feed.AgentFunction{{ID: "f", Name: "F", Tags: tags}},
		}},
	}
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	if len(proj.Entries[0].Tags) != 10 {
		t.Errorf("tags cap: got %d, want 10", len(proj.Entries[0].Tags))
	}
}

// TestFromEvent_NoFunctionsOmitsLists confirms empty capability/tag
// lists are omitted entirely rather than emitted as empty arrays.
func TestFromEvent_NoFunctionsOmitsLists(t *testing.T) {
	t.Parallel()
	item := feed.EventItem{
		LogID:            "019a7b77-ffff-7b5b-b048-d0b78f4b4c5f",
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-05-07T00:00:00Z",
		AgentID:          "330e8400-e29b-41d4-a716-446655440ddd",
		AnsName:          "ans://v1.0.0.host.example.com",
		AgentHost:        "host.example.com",
		AgentDisplayName: "Bare Agent",
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{{
			AgentURL: "https://host.example.com/mcp",
			Protocol: feed.ProtocolMCP,
		}},
	}
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatalf("FromEvent: %v", err)
	}
	b := mustMarshal(t, proj.Entries[0].Entry)
	if bytes.Contains(b, []byte(`"capabilities"`)) || bytes.Contains(b, []byte(`"tags"`)) {
		t.Errorf("empty lists must be omitted: %s", b)
	}
}

// ── Trust manifest ───────────────────────────────────────────────

func TestFromEvent_TrustManifest(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_registered.json")

	t.Run("with TLBaseURL → attestation present", func(t *testing.T) {
		t.Parallel()
		proj, err := project.FromEvent(item, defaultOpts)
		if err != nil {
			t.Fatal(err)
		}
		tm := proj.Entries[0].TrustManifest
		if tm == nil {
			t.Fatal("trust manifest missing")
		}
		if tm.Identity != "https://myagent.example.com" || tm.IdentityType != "https" {
			t.Errorf("identity: got %q/%q", tm.Identity, tm.IdentityType)
		}
		if len(tm.Attestations) != 1 {
			t.Fatalf("attestations: got %d, want 1", len(tm.Attestations))
		}
		at := tm.Attestations[0]
		wantURI := "https://tl.ans.example.org/v1/agents/550e8400-e29b-41d4-a716-446655440000/receipt"
		if at.Type != "ANS-Registration" || at.URI != wantURI ||
			at.MediaType != "application/scitt-receipt+cose" {
			t.Errorf("attestation: %+v", at)
		}
		if at.Digest != "" {
			t.Errorf("attestation must carry no digest, got %q", at.Digest)
		}
	})

	t.Run("empty TLBaseURL → no attestations", func(t *testing.T) {
		t.Parallel()
		proj, err := project.FromEvent(item, project.Options{TLBaseURL: ""})
		if err != nil {
			t.Fatal(err)
		}
		tm := proj.Entries[0].TrustManifest
		if tm == nil || tm.Identity != "https://myagent.example.com" {
			t.Fatalf("identity still expected: %+v", tm)
		}
		if len(tm.Attestations) != 0 {
			t.Errorf("empty TLBaseURL must omit attestations, got %v", tm.Attestations)
		}
	})

	t.Run("trailing-slash TLBaseURL normalized", func(t *testing.T) {
		t.Parallel()
		proj, err := project.FromEvent(item, project.Options{TLBaseURL: "https://tl.ans.example.org/"})
		if err != nil {
			t.Fatal(err)
		}
		got := proj.Entries[0].TrustManifest.Attestations[0].URI
		want := "https://tl.ans.example.org/v1/agents/550e8400-e29b-41d4-a716-446655440000/receipt"
		if got != want {
			t.Errorf("receipt URI: got %q, want %q", got, want)
		}
	})
}

// ── XOR invariant on Active entries ──────────────────────────────

// TestFromEvent_ActiveXOR proves every Active entry marshals with
// exactly url (never data, never neither) — the ARDS §3.4 value-or-
// reference invariant scoped to Active entries.
func TestFromEvent_ActiveXOR(t *testing.T) {
	t.Parallel()
	item := loadFixture(t, "testdata/event_registered.json")
	proj, err := project.FromEvent(item, defaultOpts)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range proj.Entries {
		var m map[string]any
		if err := json.Unmarshal(mustMarshal(t, e.Entry), &m); err != nil {
			t.Fatalf("entry %d unmarshal: %v", i, err)
		}
		_, hasURL := m["url"]
		_, hasData := m["data"]
		if hasURL == hasData {
			t.Errorf("entry %d violates url-XOR-data: url=%v data=%v", i, hasURL, hasData)
		}
		if !hasURL {
			t.Errorf("entry %d Active entry must carry url", i)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────

var update = boolPtr(os.Getenv("UPDATE_GOLDEN") != "")

func boolPtr(b bool) *bool { return &b }

func loadFixture(t *testing.T, path string) feed.EventItem {
	t.Helper()
	var item feed.EventItem
	if err := json.Unmarshal(mustRead(t, path), &item); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return item
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustMarshalIndent(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal indent: %v", err)
	}
	return append(b, '\n')
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// capName returns a deterministic distinct capability/tag name for the
// cap tests, zero-padded so lexical sort is stable and predictable.
func capName(i int) string {
	const digits = "0123456789"
	return "cap-" + string(digits[i/10]) + string(digits[i%10])
}
