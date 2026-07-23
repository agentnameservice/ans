package handler_test

import (
	"net/http"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agentnameservice/ans/internal/adapter/docsui"
	"github.com/agentnameservice/ans/internal/finder/handler"
)

// TestConformance_ResponseFieldsMatchSpec drives real requests through
// the handler and asserts every JSON key the responses emit is a property
// the frozen OpenAPI spec declares for that schema. This is the contract
// guard: a handler that adds, renames, or drops a wire field without the
// spec changing in lockstep fails here. It validates field NAMES (the
// part offline verifiers and clients encode against), not full JSON
// schema.
func TestConformance_ResponseFieldsMatchSpec(t *testing.T) {
	t.Parallel()
	spec := loadSpec(t)

	srv, idx := testServer(t, handler.Config{MaxPageSize: 100, DefaultPageSize: 10}, noLimit(), nil)
	seed(t, idx, activeEntry("a.example.com", "alpha", "application/mcp-server-card+json",
		"https://a.example.com/.well-known/mcp.json",
		display("Alpha Agent", "does things"), caps("Do Thing"), tags("util")))

	t.Run("SearchResponse + SearchResult + CatalogEntry", func(t *testing.T) {
		_, body := post(t, srv, "/v1/search", `{"query":{"text":"alpha"}}`)

		assertKeysDeclared(t, spec, "SearchResponse", topKeys(body))
		assertRequiredPresent(t, spec, "SearchResponse", body)

		results, _ := body["results"].([]any)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		entry := results[0].(map[string]any)
		// A SearchResult is CatalogEntry + score + source (allOf). Every
		// key must be declared on one of those two schemas, and every
		// required key from both must be present.
		assertKeysDeclaredAcross(t, spec, []string{"SearchResult", "CatalogEntry"}, topKeys(entry))
		assertRequiredPresent(t, spec, "SearchResult", entry)
		assertRequiredPresent(t, spec, "CatalogEntry", entry)

		// Nested trustManifest keys against TrustManifest + Attestation.
		tm := entry["trustManifest"].(map[string]any)
		assertKeysDeclared(t, spec, "TrustManifest", topKeys(tm))
		assertRequiredPresent(t, spec, "TrustManifest", tm)
		atts := tm["attestations"].([]any)
		att0 := atts[0].(map[string]any)
		assertKeysDeclared(t, spec, "Attestation", topKeys(att0))
		assertRequiredPresent(t, spec, "Attestation", att0)
	})

	t.Run("ExploreResponse + Facet + FacetBucket", func(t *testing.T) {
		_, body := post(t, srv, "/v1/explore",
			`{"query":{},"resultType":{"facets":[{"field":"type"}]}}`)
		assertKeysDeclared(t, spec, "ExploreResponse", topKeys(body))
		assertRequiredPresent(t, spec, "ExploreResponse", body)

		facets := body["facets"].(map[string]any)
		typeFacet := facets["type"].(map[string]any)
		assertKeysDeclared(t, spec, "Facet", topKeys(typeFacet))
		assertRequiredPresent(t, spec, "Facet", typeFacet)
		buckets := typeFacet["buckets"].([]any)
		bucket0 := buckets[0].(map[string]any)
		assertKeysDeclared(t, spec, "FacetBucket", topKeys(bucket0))
		assertRequiredPresent(t, spec, "FacetBucket", bucket0)
	})

	t.Run("Problem on 400", func(t *testing.T) {
		status, body := post(t, srv, "/v1/search", `{"query":{}}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
		assertKeysDeclared(t, spec, "Problem", topKeys(body))
	})
}

// loadSpec parses the embedded finder OpenAPI spec and returns its
// component schemas as a name→property-set map. Parsing the SAME bytes
// the binary embeds (docsui.SpecFinder) guarantees the conformance check
// reflects what ships, not a stray copy.
// specSchema is one component schema's contract surface: its declared
// property names and its required list (both flattened across inline
// allOf sub-schemas).
type specSchema struct {
	props    map[string]struct{}
	required []string
}

func loadSpec(t *testing.T) map[string]specSchema {
	t.Helper()
	// schemaNode captures both a schema's direct properties/required and
	// those contributed by inline allOf sub-schemas (SearchResult is
	// `allOf: [CatalogEntry, {properties: {score, source}}]`, so score and
	// source live in an allOf entry, not at the top level).
	type allOfNode struct {
		Properties map[string]any `yaml:"properties"`
		Required   []string       `yaml:"required"`
	}
	type schemaNode struct {
		Properties map[string]any `yaml:"properties"`
		Required   []string       `yaml:"required"`
		AllOf      []allOfNode    `yaml:"allOf"`
	}
	var doc struct {
		Components struct {
			Schemas map[string]schemaNode `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(docsui.SpecFinder.YAML, &doc); err != nil {
		t.Fatalf("parse embedded finder spec: %v", err)
	}
	out := make(map[string]specSchema, len(doc.Components.Schemas))
	for name, schema := range doc.Components.Schemas {
		s := specSchema{props: make(map[string]struct{})}
		for p := range schema.Properties {
			s.props[p] = struct{}{}
		}
		s.required = append(s.required, schema.Required...)
		for _, sub := range schema.AllOf {
			for p := range sub.Properties {
				s.props[p] = struct{}{}
			}
			s.required = append(s.required, sub.Required...)
		}
		out[name] = s
	}
	return out
}

// topKeys returns the sorted top-level keys of a decoded JSON object.
func topKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// assertKeysDeclared fails if any key is not a declared property of the
// named schema.
func assertKeysDeclared(t *testing.T, spec map[string]specSchema, schema string, keys []string) {
	t.Helper()
	s, ok := spec[schema]
	if !ok {
		t.Fatalf("spec has no schema %q", schema)
	}
	for _, k := range keys {
		if _, declared := s.props[k]; !declared {
			t.Errorf("response key %q is not declared in spec schema %q", k, schema)
		}
	}
}

// assertKeysDeclaredAcross fails if any key is not declared on at least
// one of the named schemas (for allOf-composed response shapes).
func assertKeysDeclaredAcross(t *testing.T, spec map[string]specSchema, schemas []string, keys []string) {
	t.Helper()
	for _, k := range keys {
		found := false
		for _, s := range schemas {
			if sc, ok := spec[s]; ok {
				if _, declared := sc.props[k]; declared {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("response key %q is not declared in any of %v", k, schemas)
		}
	}
}

// assertRequiredPresent fails if any property the spec marks `required`
// for the schema is absent from the sampled response object. This is the
// other half of conformance: assertKeysDeclared catches an EXTRA wire key
// the spec doesn't know about; this catches a spec-required key the
// handler DROPPED. keys is the response object's actual top-level keys.
func assertRequiredPresent(t *testing.T, spec map[string]specSchema, schema string, present map[string]any) {
	t.Helper()
	s, ok := spec[schema]
	if !ok {
		t.Fatalf("spec has no schema %q", schema)
	}
	for _, req := range s.required {
		if _, ok := present[req]; !ok {
			t.Errorf("spec-required key %q is missing from the %q response", req, schema)
		}
	}
}
