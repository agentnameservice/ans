// Package index defines the Finder's catalog index port and the query
// types its search and explore surfaces speak. The port is the boundary
// between the pure projection/poller layers and whatever store backs the
// catalog; the default adapter is a SQLite FTS5 implementation under
// internal/adapter/store/sqlitefinder.
//
// The index holds one row per projected catalog entry (an
// AGENT_REGISTERED/AGENT_RENEWED event fans out to one entry per
// discoverable endpoint, so a single agent registration can occupy
// several rows that share an ansName but differ by type/url). A
// REVOKED/DEPRECATED tombstone suppresses every row for its ansName by
// flipping their lifecycle, so a revoked agent never surfaces in search
// or explore again.
//
// All query types here are the index's own vocabulary — already parsed
// and validated by the handler. The index never sees raw HTTP shapes.
package index

import (
	"context"
	"time"

	"github.com/agentnameservice/ans/internal/finder/project"
)

// Catalog is the port the Finder's poller, search handler, and explore
// handler depend on. The poller writes (Apply, SaveCursor); the handlers
// read (Search, Explore); the server reads the cursor's freshness
// (Cursor) to compute the staleness signal.
type Catalog interface {
	// Apply writes a page of projected entries into the index and returns
	// a report of conditions the caller should log. For an Active event
	// the projected entries are the COMPLETE row set for its ansName at
	// that log position: applying them replaces every prior row for the
	// ansName (so a changed or dropped endpoint does not linger). A
	// tombstone suppresses every Active row for its ansName. Apply is
	// idempotent and replay-safe: a newer-or-equal tombstone is never
	// overridden by replaying an older Active event.
	Apply(ctx context.Context, entries []project.ProjectedEntry) (ApplyReport, error)

	// Search runs a relevance-ranked query over the Active, unexpired
	// entries and returns a page of results plus an opaque continuation
	// token. now is injected so expiry is deterministic and testable.
	Search(ctx context.Context, q SearchQuery, now time.Time) (SearchResults, error)

	// Explore aggregates the Active, unexpired matched set into facet
	// breakdowns. It never paginates: facets cover the whole matched set.
	Explore(ctx context.Context, q ExploreQuery, now time.Time) (ExploreResults, error)

	// Cursor returns the persisted feed position (the lastLogId to resume
	// polling from) and the timestamp of the last successful poll. A
	// zero LastPollOK means the index has never completed a poll.
	Cursor(ctx context.Context) (Cursor, error)

	// SaveCursor records the feed position and successful-poll time after
	// a page is durably applied. The poller calls it once per page so a
	// crash resumes from the last fully-applied page, never re-skipping.
	SaveCursor(ctx context.Context, c Cursor) error

	// Close releases the underlying store.
	Close() error
}

// Cursor is the poller's persisted position in the feed plus its
// freshness signal. LastLogID is the opaque feed cursor; LastPollOK is
// when the most recent poll round-trip succeeded (used by the server to
// decide whether to surface staleSince).
type Cursor struct {
	LastLogID  string
	LastPollOK time.Time
}

// ApplyReport carries conditions from an Apply that the caller (which
// owns the logger) should surface. It is empty on a clean apply.
type ApplyReport struct {
	// TombstoneNoOps lists revocations that suppressed zero rows while
	// Active rows for the same ansName still exist — the revoke landed but
	// had no effect, so the agent stays discoverable. The most likely
	// cause is a producer clock step-back. Each warrants an operator WARN.
	TombstoneNoOps []TombstoneNoOp
}

// TombstoneNoOp identifies a revoke/deprecate event that suppressed
// nothing despite Active rows remaining for its ansName.
type TombstoneNoOp struct {
	AnsName   string
	LogID     string
	CreatedAt string
}

// SearchQuery is the parsed, validated search request the handler hands
// the index. Text is the natural-language query (already required by the
// handler for search); Filter carries the structured constraints; Limit
// and Offset are the resolved pagination window (the handler decodes the
// opaque pageToken into an offset and re-validates it against QueryHash).
type SearchQuery struct {
	// Text is the free-text query. Empty means "match all" (explore
	// reuses SearchQuery's filter handling with an empty Text).
	Text string
	// Filter is the structured constraint set: field path → OR-set of
	// values; constraints across keys are AND-ed.
	Filter Filter
	// Limit is the maximum number of results to return (the resolved
	// pageSize, 1..max).
	Limit int
	// Offset is the zero-based start index into the deterministic result
	// order (decoded from pageToken; 0 for the first page).
	Offset int
}

// ExploreQuery is the parsed explore request: the same Text+Filter
// matched set as search, plus the facet specs to aggregate over it.
type ExploreQuery struct {
	Text   string
	Filter Filter
	Facets []FacetSpec
}

// FacetSpec requests one facet aggregation: the field path to group by,
// the maximum number of buckets to return, and a minimum count below
// which buckets are suppressed.
type FacetSpec struct {
	Field    string
	Limit    int
	MinCount int
}

// Filter is the structured constraint set. Each key is a supported field
// path; the value is the OR-set of acceptable values for that path. An
// entry matches the filter when, for every key, at least one of the
// key's values matches the entry (OR within a key, AND across keys).
//
// The handler validates field paths before constructing a Filter, so the
// index trusts every key here is supported.
type Filter map[string][]string

// Filter / facet field paths the catalog supports (ARDS §7.1, §7.3). The
// handler validates request keys against this set so an unsupported path
// becomes a 400 at the edge; the adapter trusts validated keys. Both the
// handler and the adapter import this single source of truth, so neither
// can drift from the other.
const (
	FieldType         = "type"
	FieldTags         = "tags"
	FieldCapabilities = "capabilities"
	FieldPublisher    = "publisher"
	// FieldAttestationType is the nested attestation-type path
	// (trustManifest.attestations.type).
	FieldAttestationType = "trustManifest.attestations.type"
)

// supportedFields is the set of filter/facet paths the catalog serves.
//
//nolint:gochecknoglobals // immutable lookup set; effectively a const map
var supportedFields = map[string]struct{}{
	FieldType:            {},
	FieldTags:            {},
	FieldCapabilities:    {},
	FieldPublisher:       {},
	FieldAttestationType: {},
}

// SupportedField reports whether path is a filter/facet field the catalog
// can serve. The handler rejects unsupported paths with INVALID_ARGUMENT.
func SupportedField(path string) bool {
	_, ok := supportedFields[path]
	return ok
}

// SearchResults is one page of ranked results plus the continuation
// token. NextOffset is the absolute offset to encode into the next
// pageToken; HasMore reports whether another page exists. The handler
// builds the opaque token from NextOffset and the query hash.
type SearchResults struct {
	Results    []ScoredEntry
	NextOffset int
	HasMore    bool
}

// ScoredEntry is a catalog entry annotated with its normalized relevance
// score (0..100). The entry is the wire-ready project.Entry; the handler
// wraps it with score and source for the response.
type ScoredEntry struct {
	Entry project.Entry
	Score int
}

// ExploreResults is the facet aggregation: one Facet per requested
// FacetSpec field, keyed by field path.
type ExploreResults struct {
	Facets map[string]Facet
}

// Facet is the bucket breakdown for one field: the per-value counts
// (descending by count, then value, capped at the spec's Limit) plus the
// number of matching entries that fell into buckets beyond the limit.
type Facet struct {
	Buckets    []Bucket
	OtherCount int
}

// Bucket is one facet value and the number of matching entries carrying
// it.
type Bucket struct {
	Value string
	Count int
}
