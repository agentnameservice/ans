package sqlitefinder

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

// matchedRow is one candidate entry pulled from the index before
// scoring and paging: its raw bm25 rank (when a text query ran), the
// columns the deterministic tie-break sorts on, and the verbatim entry
// JSON to return.
type matchedRow struct {
	Identifier string  `db:"identifier"`
	Type       string  `db:"type"`
	URL        string  `db:"url"`
	EntryJSON  string  `db:"entry_json"`
	Rank       float64 `db:"rank"`
}

// Search returns a relevance-ranked page of Active, unexpired entries.
//
// The matched set is computed in full (the local index is small),
// scored, and ordered deterministically before the page is sliced, so
// scores normalize consistently across pages and the order is stable for
// a given query regardless of pageToken. With a text query the order is
// (score desc, identifier, type, url) where score derives from bm25;
// without one, every match scores 100 and the order is
// (identifier, type, url).
func (s *Store) Search(ctx context.Context, q index.SearchQuery, now time.Time) (index.SearchResults, error) {
	rows, err := s.matchedRows(ctx, q.Text, q.Filter, now)
	if err != nil {
		return index.SearchResults{}, err
	}

	scored := scoreAndSort(rows, q.Text != "")

	// Slice the requested page. A negative or out-of-range offset yields
	// an empty page with no error — a stale token is not a server fault.
	total := len(scored)
	start := q.Offset
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := start + q.Limit
	if q.Limit <= 0 || end > total {
		end = total
	}

	page := scored[start:end]
	results := make([]index.ScoredEntry, 0, len(page))
	for _, r := range page {
		var entry project.Entry
		if err := json.Unmarshal([]byte(r.row.EntryJSON), &entry); err != nil {
			return index.SearchResults{}, fmt.Errorf("sqlitefinder: unmarshal entry: %w", err)
		}
		results = append(results, index.ScoredEntry{Entry: entry, Score: r.score})
	}

	return index.SearchResults{
		Results:    results,
		NextOffset: end,
		HasMore:    end < total,
	}, nil
}

// matchedRows runs the filtered (and optionally full-text) query and
// returns every matching candidate. now bounds expiry: a row with a
// non-empty expires_at at or before now is excluded.
func (s *Store) matchedRows(ctx context.Context, text string, filter index.Filter, now time.Time) ([]matchedRow, error) {
	where := []string{"e.lifecycle = 'ACTIVE'", "(e.expires_at = '' OR e.expires_at > ?)"}
	args := []any{rfc3339(now)}

	match := buildMatchQuery(text)
	from := "finder_entries e"
	rankExpr := "0.0 AS rank"
	if match != "" {
		// Join the FTS table by rowid; MATCH constrains, bm25 ranks
		// (more-negative = more relevant).
		from = "finder_entries e JOIN finder_entries_fts f ON f.rowid = e.rowid"
		where = append(where, "finder_entries_fts MATCH ?")
		args = append(args, match)
		rankExpr = "bm25(finder_entries_fts) AS rank"
	}

	filterClauses, filterArgs, err := buildFilterClauses(filter)
	if err != nil {
		return nil, err
	}
	where = append(where, filterClauses...)
	args = append(args, filterArgs...)

	// from/rankExpr/where are built from fixed identifiers and field maps,
	// never user input; every value is a bound parameter, so this is
	// injection-safe despite the Sprintf assembly.
	query := fmt.Sprintf(
		`SELECT e.identifier, e.type, e.url, e.entry_json, %s FROM %s WHERE %s`,
		rankExpr, from, strings.Join(where, " AND "))

	var rows []matchedRow
	if err := s.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("sqlitefinder: search query: %w", err)
	}
	return rows, nil
}

// scoredRow pairs a candidate with its normalized 0-100 score.
type scoredRow struct {
	row   matchedRow
	score int
}

// scoreAndSort normalizes raw bm25 ranks into 0-100 scores and orders the
// result set deterministically.
//
// Scoring: with no text query every match is equally relevant, so all
// score 100. With a text query, bm25 ranks (more-negative = better) are
// linearly mapped so the best match is 100 and the worst is 0; when every
// match shares one rank (a single result, or identical relevance) they
// all score 100.
//
// Ordering: primary key is score descending; ties break on
// (identifier, type, url) so the order — and thus pagination — is stable
// for a given query.
func scoreAndSort(rows []matchedRow, hasText bool) []scoredRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]scoredRow, len(rows))
	if !hasText {
		for i, r := range rows {
			out[i] = scoredRow{row: r, score: 100}
		}
		sortScored(out)
		return out
	}

	best, worst := rows[0].Rank, rows[0].Rank
	for _, r := range rows {
		if r.Rank < best {
			best = r.Rank // more negative = more relevant
		}
		if r.Rank > worst {
			worst = r.Rank
		}
	}
	span := worst - best
	for i, r := range rows {
		score := 100
		if span > 0 {
			// best (most negative) → 100, worst → 0.
			score = int((worst - r.Rank) / span * 100)
		}
		out[i] = scoredRow{row: r, score: score}
	}
	sortScored(out)
	return out
}

// sortScored applies the (score desc, identifier, type, url) order.
func sortScored(rows []scoredRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if a.row.Identifier != b.row.Identifier {
			return a.row.Identifier < b.row.Identifier
		}
		if a.row.Type != b.row.Type {
			return a.row.Type < b.row.Type
		}
		return a.row.URL < b.row.URL
	})
}

// rfc3339 renders now as a UTC, second-precision RFC 3339 string for the
// "expires_at > ?" filter in search.go and explore.go. That comparison
// is lexical (expires_at is a TEXT column), so it is chronologically
// correct only when the stored values share this exact rendering. The
// finder stores feed timestamps verbatim — project.ProjectedEntry
// carries the producer's createdAt/expiresAt unchanged, it does not
// normalize them — so soundness depends on the RA emitting canonical UTC
// RFC 3339 (trailing "Z", no sub-second digits). A producer that emitted
// a zone offset or fractional seconds would compare incorrectly here.
func rfc3339(now time.Time) string {
	return now.UTC().Format(time.RFC3339)
}
