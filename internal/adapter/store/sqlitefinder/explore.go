package sqlitefinder

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/finder/index"
)

// Explore aggregates the Active, unexpired matched set into facet
// breakdowns — one Facet per requested FacetSpec.Field. The matched set
// is the same predicate search uses (text MATCH + filters + active +
// unexpired); explore never paginates, so facets always cover the whole
// matched set.
//
// For each facet the store counts matching entries grouped by the field
// value, drops buckets below MinCount, orders the survivors by count
// descending then value ascending (a deterministic tie-break), keeps the
// top Limit, and reports the matching-entry count in the dropped buckets
// as OtherCount.
func (s *Store) Explore(ctx context.Context, q index.ExploreQuery, now time.Time) (index.ExploreResults, error) {
	facets := make(map[string]index.Facet, len(q.Facets))
	for _, spec := range q.Facets {
		f, err := s.facetFor(ctx, spec, q.Text, q.Filter, now)
		if err != nil {
			return index.ExploreResults{}, err
		}
		facets[spec.Field] = f
	}
	return index.ExploreResults{Facets: facets}, nil
}

// facetFor computes one facet over the matched set.
func (s *Store) facetFor(
	ctx context.Context, spec index.FacetSpec, text string, filter index.Filter, now time.Time,
) (index.Facet, error) {
	where, args, err := s.matchedSetWhere(text, filter, now)
	if err != nil {
		return index.Facet{}, err
	}

	// The grouped value comes from a fixed column (scalar field) or a
	// side-table join (multi-valued field). Field identifiers are never
	// interpolated from input; spec.Field is validated upstream.
	var query string
	if table, ok := sideTableForField(spec.Field); ok {
		// table is from a fixed map (never user input); where uses bound params.
		query = fmt.Sprintf(`
            SELECT st.value AS value, COUNT(DISTINCT e.rowid) AS count
              FROM finder_entries e
              JOIN %s st ON st.entry_rowid = e.rowid
             WHERE %s
          GROUP BY st.value`, table, where)
	} else {
		col, ok := scalarColumnForField(spec.Field)
		if !ok {
			return index.Facet{}, fmt.Errorf("sqlitefinder: unsupported facet field %q", spec.Field)
		}
		// col is from a fixed map (never user input); where uses bound params.
		query = fmt.Sprintf(`
            SELECT e.%s AS value, COUNT(*) AS count
              FROM finder_entries e
             WHERE %s
          GROUP BY e.%s`, col, where, col)
	}

	rawBuckets, err := s.scanBuckets(ctx, query, args)
	if err != nil {
		return index.Facet{}, err
	}
	return assembleFacet(rawBuckets, spec), nil
}

// bucketRow is one (value, count) group before MinCount/Limit are applied.
type bucketRow struct {
	Value string `db:"value"`
	Count int    `db:"count"`
}

func (s *Store) scanBuckets(ctx context.Context, query string, args []any) ([]bucketRow, error) {
	var rows []bucketRow
	if err := s.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("sqlitefinder: facet query: %w", err)
	}
	return rows, nil
}

// assembleFacet sorts the raw buckets deterministically (count desc,
// value asc), applies MinCount, then keeps the top Limit. OtherCount is
// the number of matching entries in the buckets that survived MinCount
// but fell beyond Limit — buckets dropped by MinCount are not counted as
// "other" (they were suppressed, not paged out).
func assembleFacet(raw []bucketRow, spec index.FacetSpec) index.Facet {
	kept := make([]bucketRow, 0, len(raw))
	for _, b := range raw {
		if b.Count >= spec.MinCount {
			kept = append(kept, b)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Count != kept[j].Count {
			return kept[i].Count > kept[j].Count
		}
		return kept[i].Value < kept[j].Value
	})

	limit := spec.Limit
	if limit <= 0 {
		limit = len(kept)
	}
	var other int
	buckets := make([]index.Bucket, 0, min(limit, len(kept)))
	for i, b := range kept {
		if i < limit {
			buckets = append(buckets, index.Bucket{Value: b.Value, Count: b.Count})
			continue
		}
		other += b.Count
	}
	return index.Facet{Buckets: buckets, OtherCount: other}
}

// matchedSetWhere builds the shared "Active, unexpired, text+filter
// matched" predicate explore facets aggregate over. Unlike search it
// expresses the FTS constraint as an EXISTS subquery rather than a join,
// so a facet that groups by a side-table value does not multiply rows by
// the FTS join.
func (s *Store) matchedSetWhere(text string, filter index.Filter, now time.Time) (string, []any, error) {
	where := []string{"e.lifecycle = 'ACTIVE'", "(e.expires_at = '' OR e.expires_at > ?)"}
	args := []any{rfc3339(now)}

	if match := buildMatchQuery(text); match != "" {
		where = append(where,
			"EXISTS (SELECT 1 FROM finder_entries_fts f WHERE f.rowid = e.rowid AND finder_entries_fts MATCH ?)")
		args = append(args, match)
	}

	clauses, filterArgs, err := buildFilterClauses(filter)
	if err != nil {
		return "", nil, err
	}
	where = append(where, clauses...)
	args = append(args, filterArgs...)

	return strings.Join(where, " AND "), args, nil
}

// scalarColumnForField maps a scalar facet/filter field to its
// finder_entries column. The second result is false for multi-valued
// fields (handled via side-tables).
func scalarColumnForField(field string) (string, bool) {
	switch field {
	case index.FieldType:
		return "type", true
	case index.FieldPublisher:
		return "publisher", true
	default:
		return "", false
	}
}
