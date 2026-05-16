package lei

// Conformance tests driven by the JSON fixtures at
// docs/tests/conformance/anchor-0c-lei/. Validates the LEI
// resolver's Canonicalize against real public LEIs from the GLEIF
// Global LEI Index, lowercase + whitespace normalization, and the
// negative cases the resolver MUST reject. The fixture file is
// language-agnostic; an external Rust or Python implementation can
// consume the same JSON to validate its conformance.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/godaddy/ans/internal/domain"
)

type leiVector struct {
	Label                string `json:"label"`
	LEI                  string `json:"lei"`
	LOUPrefix            string `json:"louPrefix"`
	ExpectedCanonicalize string `json:"expectedCanonicalize"`
	Notes                string `json:"notes"`
}

type lowercaseVector struct {
	Label             string `json:"label"`
	Input             string `json:"input"`
	ExpectedCanonical string `json:"expectedCanonical"`
}

type rejectVector struct {
	Label        string `json:"label"`
	Input        string `json:"input"`
	ExpectedCode string `json:"expectedCode"`
}

type conformanceFixture struct {
	Vectors         []leiVector       `json:"vectors"`
	LowercaseInputs []lowercaseVector `json:"lowercaseInputs"`
	RejectVectors   []rejectVector    `json:"rejectVectors"`
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "docs", "tests",
		"conformance", "anchor-0c-lei", "lei-public-examples.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var f conformanceFixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func TestConformance_PublicLEIs(t *testing.T) {
	fixture := loadConformanceFixture(t)
	if len(fixture.Vectors) < 4 {
		t.Fatalf("expected at least 4 public-LEI vectors, got %d", len(fixture.Vectors))
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Label, func(t *testing.T) {
			got, err := Canonicalize(v.LEI)
			if err != nil {
				t.Fatalf("Canonicalize(%q) failed: %v\n  notes: %s", v.LEI, err, v.Notes)
			}
			if got != v.LEI {
				t.Errorf("Canonicalize(%q) = %q (already-canonical input should pass through)",
					v.LEI, got)
			}
			// Cross-check the LOU prefix: first 4 characters of the canonical form.
			if len(got) >= 4 && v.LOUPrefix != "" {
				if got[:4] != v.LOUPrefix {
					t.Errorf("LOU prefix mismatch: got %q, want %q", got[:4], v.LOUPrefix)
				}
			}
		})
	}
}

func TestConformance_LowercaseAndWhitespace(t *testing.T) {
	fixture := loadConformanceFixture(t)
	for _, v := range fixture.LowercaseInputs {
		t.Run(v.Label, func(t *testing.T) {
			got, err := Canonicalize(v.Input)
			if err != nil {
				t.Fatalf("Canonicalize(%q) failed: %v", v.Input, err)
			}
			if got != v.ExpectedCanonical {
				t.Errorf("Canonicalize(%q) = %q, want %q", v.Input, got, v.ExpectedCanonical)
			}
		})
	}
}

func TestConformance_RejectVectors(t *testing.T) {
	fixture := loadConformanceFixture(t)
	for _, v := range fixture.RejectVectors {
		t.Run(v.Label, func(t *testing.T) {
			_, err := Canonicalize(v.Input)
			if err == nil {
				t.Fatalf("Canonicalize(%q) should reject, got success", v.Input)
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) {
				t.Fatalf("error is not *domain.Error: %T", err)
			}
			if dErr.Code != v.ExpectedCode {
				t.Errorf("Canonicalize(%q) code = %q, want %q",
					v.Input, dErr.Code, v.ExpectedCode)
			}
		})
	}
}
