package docsui_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/adapter/docsui"
)

// TestMount_ServesBothRoutes verifies the Mount helper wires both
// the spec and the HTML page. Use the TL spec — shape is identical
// for the RA path.
func TestMount_ServesBothRoutes(t *testing.T) {
	r := chi.NewRouter()
	docsui.Mount(r, docsui.SpecTL)

	t.Run("openapi.yaml", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/yaml") {
			t.Errorf("content-type: got %q want text/yaml", ct)
		}
		body := rec.Body.String()
		// Spec is valid OpenAPI — first line starts with `openapi:`
		// when YAML-serialized from our source files.
		if !strings.Contains(body, "openapi: 3.0.3") {
			t.Errorf("body missing openapi header; first 80 bytes: %q", body[:min(80, len(body))])
		}
	})

	t.Run("html page", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/docs", nil)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("content-type: got %q want text/html", ct)
		}
		body := rec.Body.String()
		for _, want := range []string{
			"<title>",
			"swagger-ui.css",
			"swagger-ui-bundle.js",
			`url: "/docs/openapi.yaml"`,
			docsui.SpecTL.Title,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("HTML body missing %q", want)
			}
		}
	})
}

// TestEmbeddedSpecs_MatchCanonical guards against drift between
// spec/api-spec-*.yaml and the copies embedded under
// internal/adapter/docsui/openapi/. A developer who edits one
// without the other must see the failure here before the binary
// ships a stale spec. `make docs-sync` fixes it.
func TestEmbeddedSpecs_MatchCanonical(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))

	pairs := []struct {
		canonical string
		embedded  []byte
		label     string
	}{
		{filepath.Join(repoRoot, "spec", "api-spec-v2.yaml"), docsui.SpecRA.YAML, "ra"},
		{filepath.Join(repoRoot, "spec", "api-spec-tl-v2.yaml"), docsui.SpecTL.YAML, "tl"},
		{filepath.Join(repoRoot, "spec", "api-spec-finder-v1.yaml"), docsui.SpecFinder.YAML, "finder"},
	}
	for _, p := range pairs {
		t.Run(p.label, func(t *testing.T) {
			f, err := os.Open(p.canonical)
			if err != nil {
				t.Fatalf("open canonical: %v", err)
			}
			defer f.Close()
			canon, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("read canonical: %v", err)
			}
			if !bytes.Equal(canon, p.embedded) {
				t.Fatalf("embedded %s spec drifted from %s — run `make docs-sync`",
					p.label, p.canonical)
			}
		})
	}
}
