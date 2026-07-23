package handler

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/agentnameservice/ans/internal/finder/index"
)

// Federation modes (spec Federation enum). auto/none both merge a
// zero-upstream set in this single-registry Finder, so they are
// equivalent to local-only here; referrals additionally returns the
// configured registry entries.
const (
	federationAuto      = "auto"
	federationReferrals = "referrals"
	federationNone      = "none"
)

// Request-cost caps. The discovery surface is unauthenticated and the
// rate limiter prices every request equally, so a single request must not
// be able to force unbounded work. These bound the inputs that drive
// query cost before they reach the index:
//
//   - maxTextBytes / maxTextTokens cap the free-text query (FTS5 MATCH
//     cost grows with token count);
//   - maxFilterValues caps total filter values across all keys (each
//     becomes a bound SQL parameter; SQLite's variable limit is ~32k, and
//     a huge IN-list is expensive well before that);
//   - maxFacets caps the number of facets per explore (each facet is a
//     separate GROUP BY scan; there are only 5 supported fields, so more
//     than 5 — or any duplicate — is meaningless).
//
// Over-limit inputs are rejected with 400 INVALID_ARGUMENT rather than
// silently truncated, so a client learns its request was malformed.
const (
	maxTextBytes    = 4 << 10 // 4 KiB
	maxTextTokens   = 64
	maxFilterValues = 100
	maxFacets       = 5
)

// validateQueryBounds enforces the per-request cost caps and text hygiene
// on the shared query object (text + filter). Called by both handlers
// before the query reaches the index.
func validateQueryBounds(q queryDTO) error {
	if len(q.Text) > maxTextBytes {
		return fmt.Errorf("query.text exceeds the %d-byte limit", maxTextBytes)
	}
	// Reject control (Cc) and format (Cf) runes in the query text rather
	// than letting them reach FTS5 (where a NUL or other control byte
	// surfaces as an opaque 500 plus error-log noise). 400 is the honest
	// answer: the input is malformed.
	if r, bad := firstDisallowedRune(q.Text); bad {
		return fmt.Errorf("query.text contains a disallowed control/format character U+%04X", r)
	}
	if n := len(strings.Fields(q.Text)); n > maxTextTokens {
		return fmt.Errorf("query.text has %d tokens, exceeding the limit of %d", n, maxTextTokens)
	}
	total := 0
	for _, values := range q.Filter {
		total += len(values)
	}
	if total > maxFilterValues {
		return fmt.Errorf("query.filter has %d values, exceeding the limit of %d", total, maxFilterValues)
	}
	return nil
}

// validateSearch validates a search request and returns the parsed query,
// resolved federation mode, and resolved page size. Per the spec,
// query.text is REQUIRED for search; an empty/whitespace text is a 400.
func (h *Handler) validateSearch(req searchRequest) (queryDTO, string, int, error) {
	if strings.TrimSpace(req.Query.Text) == "" {
		return queryDTO{}, "", 0, errors.New("query.text is required for search")
	}
	if err := validateQueryBounds(req.Query); err != nil {
		return queryDTO{}, "", 0, err
	}
	if err := validateFilter(req.Query.Filter); err != nil {
		return queryDTO{}, "", 0, err
	}

	federation, err := resolveFederation(req.Federation)
	if err != nil {
		return queryDTO{}, "", 0, err
	}

	pageSize, err := h.resolvePageSize(req.PageSize)
	if err != nil {
		return queryDTO{}, "", 0, err
	}

	return req.Query, federation, pageSize, nil
}

// validateExplore validates an explore request and returns the parsed
// query and facet specs. Per the spec, query.text and query.filter are
// both optional for explore; resultType.facets is required and each facet
// must name a supported field.
func (h *Handler) validateExplore(req exploreRequest) (queryDTO, []index.FacetSpec, error) {
	if err := validateQueryBounds(req.Query); err != nil {
		return queryDTO{}, nil, err
	}
	if err := validateFilter(req.Query.Filter); err != nil {
		return queryDTO{}, nil, err
	}
	if len(req.ResultType.Facets) == 0 {
		return queryDTO{}, nil, errors.New("resultType.facets must contain at least one facet")
	}
	if len(req.ResultType.Facets) > maxFacets {
		return queryDTO{}, nil, fmt.Errorf("resultType.facets has %d entries, exceeding the limit of %d",
			len(req.ResultType.Facets), maxFacets)
	}

	facets := make([]index.FacetSpec, 0, len(req.ResultType.Facets))
	seen := make(map[string]struct{}, len(req.ResultType.Facets))
	for _, f := range req.ResultType.Facets {
		if strings.TrimSpace(f.Field) == "" {
			return queryDTO{}, nil, errors.New("facet.field is required")
		}
		if !index.SupportedField(f.Field) {
			return queryDTO{}, nil, fmt.Errorf("facet field %q is not a supported field path", f.Field)
		}
		if _, dup := seen[f.Field]; dup {
			return queryDTO{}, nil, fmt.Errorf("facet field %q is requested more than once", f.Field)
		}
		seen[f.Field] = struct{}{}
		limit := defaultFacetLimit
		if f.Limit != nil {
			if *f.Limit < 1 {
				return queryDTO{}, nil, errors.New("facet.limit must be >= 1")
			}
			limit = *f.Limit
		}
		minCount := 0
		if f.MinCount != nil {
			if *f.MinCount < 0 {
				return queryDTO{}, nil, errors.New("facet.minCount must be >= 0")
			}
			minCount = *f.MinCount
		}
		facets = append(facets, index.FacetSpec{Field: f.Field, Limit: limit, MinCount: minCount})
	}
	return req.Query, facets, nil
}

// validateFilter rejects any filter key that is not a supported field
// path (ARDS §7.1 allows a registry to 400 an unsupported path). An empty
// filter is valid. A key mapping to an empty value array is rejected — a
// constraint with no acceptable values is meaningless and most likely a
// client bug. (A bare scalar reaches here already wrapped as a
// single-element slice by filterValues.UnmarshalJSON, so it passes.)
func validateFilter(filter map[string]filterValues) error {
	for key, values := range filter {
		if !index.SupportedField(key) {
			return fmt.Errorf("filter field %q is not a supported field path", key)
		}
		if len(values) == 0 {
			return fmt.Errorf("filter field %q has no values", key)
		}
		for _, v := range values {
			if v == "" {
				return fmt.Errorf("filter field %q has an empty value", key)
			}
		}
	}
	return nil
}

// resolveFederation maps the request's federation field to a canonical
// mode, defaulting to auto when omitted (spec default). An unrecognized
// value is a 400.
func resolveFederation(raw string) (string, error) {
	switch raw {
	case "":
		return federationAuto, nil
	case federationAuto, federationReferrals, federationNone:
		return raw, nil
	default:
		return "", fmt.Errorf("federation %q is not one of auto, referrals, none", raw)
	}
}

// resolvePageSize clamps and validates the requested page size. Omitted →
// the configured default; out-of-range low (< 1) is a 400; above the
// configured max is clamped down to the max (the spec caps at 100, which
// the handler enforces via MaxPageSize).
func (h *Handler) resolvePageSize(requested *int) (int, error) {
	if requested == nil {
		return h.cfg.DefaultPageSize, nil
	}
	if *requested < 1 {
		return 0, errors.New("pageSize must be >= 1")
	}
	if *requested > h.cfg.MaxPageSize {
		return h.cfg.MaxPageSize, nil
	}
	return *requested, nil
}

// firstDisallowedRune reports the first control (Cc) or format (Cf) rune
// in s and true, or (0, false) when s is clean. These categories cover
// NUL and the C0/C1 controls plus the bidi/zero-width format characters —
// the same classes the projection layer strips from emitted text, but on
// query input we reject rather than strip so the caller learns the input
// was malformed.
func firstDisallowedRune(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return r, true
		}
	}
	return 0, false
}
