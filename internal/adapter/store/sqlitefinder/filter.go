package sqlitefinder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agentnameservice/ans/internal/finder/index"
)

// The supported filter/facet field paths are defined once on the index
// port (index.Field*); the adapter maps each to its storage location. A
// path the handler did not pre-validate is rejected here as a defensive
// fail-closed (see buildFilterClauses).

// sideTableForField maps a multi-valued field path to the side-table its
// values live in. The second result is false for the scalar fields
// (type, publisher) that live on finder_entries directly.
func sideTableForField(field string) (string, bool) {
	switch field {
	case index.FieldTags:
		return "finder_entry_tags", true
	case index.FieldCapabilities:
		return "finder_entry_capabilities", true
	case index.FieldAttestationType:
		return "finder_entry_attestation_types", true
	default:
		return "", false
	}
}

// buildFilterClauses turns a filter into SQL WHERE fragments (joined by
// the caller with AND) plus the positional args. Each field contributes
// one fragment; within a field the values OR together. Scalar fields
// (type, publisher) compare a finder_entries column; multi-valued fields
// use an EXISTS over the field's side-table. Field paths are mapped to
// fixed identifiers (never interpolated from input), and every value is
// a bound parameter, so this is injection-safe.
//
// An unsupported filter key is rejected with an error rather than
// silently dropped: silently ignoring an AND constraint would widen the
// matched set, returning results the caller asked to exclude. The
// handler validates keys before reaching here, so this is a defensive
// fail-closed for a contract violation. A key with an empty value list
// contributes no constraint (it neither narrows nor widens).
func buildFilterClauses(filter map[string][]string) ([]string, []any, error) {
	clauses := make([]string, 0, len(filter))
	var args []any

	// Keys sorted so the generated SQL (and its arg order) is deterministic.
	keys := make([]string, 0, len(filter))
	for k := range filter {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, field := range keys {
		values := filter[field]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")

		switch field {
		case index.FieldType:
			if len(values) == 0 {
				continue
			}
			clauses = append(clauses, fmt.Sprintf("e.type IN (%s)", placeholders))
		case index.FieldPublisher:
			if len(values) == 0 {
				continue
			}
			clauses = append(clauses, fmt.Sprintf("e.publisher IN (%s)", placeholders))
		default:
			table, ok := sideTableForField(field)
			if !ok {
				return nil, nil, fmt.Errorf("sqlitefinder: unsupported filter field %q", field)
			}
			if len(values) == 0 {
				continue
			}
			clauses = append(clauses, fmt.Sprintf(
				"EXISTS (SELECT 1 FROM %s st WHERE st.entry_rowid = e.rowid AND st.value IN (%s))",
				table, placeholders))
		}
		args = append(args, valuesAsArgs(values)...)
	}
	return clauses, args, nil
}

// valuesAsArgs widens a string slice to a []any for positional binding.
func valuesAsArgs(values []string) []any {
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
	}
	return args
}
