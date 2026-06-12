package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"sort"

	"github.com/godaddy/ans/internal/finder/project"
)

// ── Request DTOs (spec/api-spec-finder-v1.yaml) ──────────────────────

// searchRequest is the POST /v1/search body. Field names match the
// frozen spec's SearchRequest exactly.
type searchRequest struct {
	Query      queryDTO `json:"query"`
	Federation string   `json:"federation,omitempty"`
	PageSize   *int     `json:"pageSize,omitempty"`
	PageToken  string   `json:"pageToken,omitempty"`
}

// exploreRequest is the POST /v1/explore body (spec ExploreRequest).
type exploreRequest struct {
	Query      queryDTO          `json:"query"`
	ResultType exploreResultType `json:"resultType"`
}

// queryDTO is the shared Query object (spec Query): a free-text string
// plus a structured filter of dot-path keys → value sets.
type queryDTO struct {
	Text   string                  `json:"text,omitempty"`
	Filter map[string]filterValues `json:"filter,omitempty"`
}

// filterValues is the value side of a filter constraint. The frozen spec
// (Filter schema) says "A bare scalar is accepted as a single-element
// array," so this unmarshals from EITHER a JSON string ("finance") or a
// JSON array of strings (["finance","travel"]). A plain
// map[string][]string would reject the scalar form with a 400, breaking
// the contract.
type filterValues []string

// UnmarshalJSON accepts a JSON string or a JSON array of strings. Any
// other shape (number, object, array-of-non-strings) is an error the
// handler maps to INVALID_ARGUMENT.
func (fv *filterValues) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []string
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return errors.New("filter value array must contain only strings")
		}
		*fv = arr
		return nil
	}
	var single string
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return errors.New("filter value must be a string or an array of strings")
	}
	*fv = filterValues{single}
	return nil
}

// asIndexFilter converts the wire filter (string-or-array values) into the
// index's filter shape (plain string slices).
func (q queryDTO) asIndexFilter() map[string][]string {
	if len(q.Filter) == 0 {
		return nil
	}
	out := make(map[string][]string, len(q.Filter))
	for k, v := range q.Filter {
		out[k] = []string(v)
	}
	return out
}

// exploreResultType is the spec ExploreResultType: the facet specs to
// aggregate.
type exploreResultType struct {
	Facets []facetSpecDTO `json:"facets"`
}

// facetSpecDTO is one spec FacetSpec.
type facetSpecDTO struct {
	Field    string `json:"field"`
	Limit    *int   `json:"limit,omitempty"`
	MinCount *int   `json:"minCount,omitempty"`
}

// ── Response DTOs ────────────────────────────────────────────────────

// searchResponse is the spec SearchResponse. Results embed the full
// CatalogEntry plus score and source; referrals are config-supplied
// registry entries; nextPageToken continues paging. staleSince is the
// additive pre-release field signaling the index is serving past the
// configured freshness bound (omitted when fresh).
type searchResponse struct {
	Results       []searchResult  `json:"results"`
	Referrals     []project.Entry `json:"referrals,omitempty"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
	StaleSince    string          `json:"staleSince,omitempty"`
}

// searchResult is a CatalogEntry annotated with score + source (spec
// SearchResult). It flattens the entry via an inline marshal so the
// response carries the entry's fields at the top level alongside score
// and source, matching the spec's allOf composition.
type searchResult struct {
	project.Entry
	Score  int    `json:"score"`
	Source string `json:"source"`
}

// exploreResponse is the spec ExploreResponse: a fixed resultType plus a
// map of field path → facet breakdown.
type exploreResponse struct {
	ResultType string              `json:"resultType"`
	Facets     map[string]facetDTO `json:"facets"`
	StaleSince string              `json:"staleSince,omitempty"`
}

// facetDTO is the spec Facet: buckets plus the beyond-limit count.
type facetDTO struct {
	Buckets    []facetBucketDTO `json:"buckets"`
	OtherCount int              `json:"otherCount,omitempty"`
}

// facetBucketDTO is the spec FacetBucket.
type facetBucketDTO struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// ── pageToken codec ──────────────────────────────────────────────────

// pageToken carries an absolute result offset plus a hash of the query it
// belongs to. Binding the token to its query means a token minted for one
// query cannot be replayed against a different one (which would page into
// an unrelated result set); a mismatch is rejected as INVALID_ARGUMENT.
// The token is opaque base64 to the client.
type pageToken struct {
	Offset    uint64
	QueryHash uint64
}

// queryHash derives a stable 64-bit fingerprint of the query a page
// belongs to (text + filter). Two requests that would produce the same
// ordered result set share a hash; any change to text or filter changes
// it, invalidating an old token.
func queryHash(text string, filter map[string][]string) uint64 {
	h := sha256.New()
	h.Write([]byte(text))
	h.Write([]byte{0})
	// Filter is a map; hash it in a canonical (sorted) order so the same
	// logical filter always hashes identically regardless of JSON key
	// order on the wire.
	for _, k := range sortedKeys(filter) {
		h.Write([]byte(k))
		h.Write([]byte{0})
		for _, v := range filter[k] {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// encodePageToken renders a pageToken as an opaque URL-safe base64 string.
// The offset is a result-set index, always non-negative; it is stored as
// an unsigned 64-bit value so there is no signed conversion to overflow.
func encodePageToken(t pageToken) string {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], t.Offset)
	binary.BigEndian.PutUint64(buf[8:16], t.QueryHash)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodePageToken parses an opaque token. A malformed token, one whose
// offset exceeds the platform int range, or one whose query hash does not
// match the current query is an error the caller maps to
// INVALID_ARGUMENT.
func decodePageToken(s string, wantHash uint64) (pageToken, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageToken{}, errors.New("pageToken is not valid base64")
	}
	if len(raw) != 16 {
		return pageToken{}, errors.New("pageToken has wrong length")
	}
	t := pageToken{
		Offset:    binary.BigEndian.Uint64(raw[0:8]),
		QueryHash: binary.BigEndian.Uint64(raw[8:16]),
	}
	// The offset must round-trip into an int (the index's Offset type)
	// without overflow on a 32-bit platform; a token claiming a larger
	// offset is malformed.
	if t.Offset > math.MaxInt32 {
		return pageToken{}, errors.New("pageToken offset out of range")
	}
	if t.QueryHash != wantHash {
		return pageToken{}, errors.New("pageToken does not match this query")
	}
	return t, nil
}

// sortedKeys returns a map's keys in ascending order.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
