// Package docsui serves the OpenAPI spec + a Swagger-UI page for the
// currently-running binary. Both ans-ra and ans-tl mount it at /docs
// so an operator can hit http://localhost:18080/docs or :18081/docs and
// explore routes interactively.
//
// Design: Swagger UI itself loads from a CDN (jsdelivr) — that keeps
// the binary small and guarantees the UI stays current. The API spec
// is embedded at compile time so what the UI displays is always what
// the server compiled against (no drift between deployed binary and
// its docs). Operators that need air-gapped UI can swap in any
// Swagger UI / Redoc bundle on disk and point to the same YAML URL.
package docsui

import (
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Spec holds the YAML bytes + a human-readable title for one API.
// ans-ra passes SpecRA, ans-tl passes SpecTL.
type Spec struct {
	// YAML is the raw spec bytes. Served at `/docs/openapi.yaml`
	// with `text/yaml` content-type.
	YAML []byte
	// Title shows up as the page title + heading in the Swagger UI.
	Title string
}

// Embedded spec files. Paths are relative to this file; the //go:embed
// directive runs at compile time and bakes the YAML into the binary.
// When the files change, the embed is refreshed on the next build —
// which is why we point at the canonical spec/ location rather than
// maintaining a second copy under internal/.

//go:embed openapi/ra.yaml
var raYAML []byte

//go:embed openapi/tl.yaml
var tlYAML []byte

//go:embed openapi/finder.yaml
var finderYAML []byte

// SpecRA is the spec for ans-ra — the V2 RA OpenAPI contract.
//
//nolint:gochecknoglobals // immutable bundle of embedded YAML + title; effectively a const
var SpecRA = Spec{YAML: raYAML, Title: "ans-ra — Registration Authority API"}

// SpecTL is the spec for ans-tl — the V2 TL OpenAPI contract.
//
//nolint:gochecknoglobals // immutable bundle of embedded YAML + title; effectively a const
var SpecTL = Spec{YAML: tlYAML, Title: "ans-tl — Transparency Log API"}

// SpecFinder is the spec for ans-finder — the ARD discovery contract.
//
//nolint:gochecknoglobals // immutable bundle of embedded YAML + title; effectively a const
var SpecFinder = Spec{YAML: finderYAML, Title: "ans-finder — Agentic Resource Discovery API"}

// Mount registers the docs routes on r:
//
//	GET /docs              — HTML page loading Swagger UI + the spec
//	GET /docs/openapi.yaml — raw spec bytes (text/yaml)
//
// Callers must exclude both paths from any auth middleware — local
// API docs should be readable without credentials. For static-key
// setups, pass `auth.WithAnonymousPath("/docs")` when building the
// provider. (The single prefix covers both routes.)
func Mount(r chi.Router, spec Spec) {
	r.Get("/docs/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// spec.YAML is an embedded file (go:embed) served as text/yaml, not HTML; no user input.
		_, _ = w.Write(spec.YAML)
	})
	r.Get("/docs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// renderSwaggerUI is a compile-time-constant HTML template; the only interpolated value
		// (spec.Title) is HTML-escaped inside renderSwaggerUI (see `safeTitle`) and sourced from
		// a caller-owned Spec literal — not user input.
		_, _ = w.Write([]byte(renderSwaggerUI(spec.Title)))
	})
}

// renderSwaggerUI returns the HTML page that loads Swagger UI from
// jsdelivr and points it at /docs/openapi.yaml. Kept as a plain
// string template rather than a text/template so there's no
// runtime parsing cost on the hot path (the page is static per
// deploy).
//
// Swagger UI's standalone preset handles navigation + "Try it out"
// by itself — we pass it only the OpenAPI URL and a few cosmetic
// options. dom_id anchors the app into the page body.
func renderSwaggerUI(title string) string {
	// Pin the Swagger UI version so upstream changes can't break
	// local dev overnight. 5.17.x is the current LTS-ish series
	// at the time of writing and works against OpenAPI 3.0 specs.
	const swaggerVersion = "5.17.14"
	// Escape the title in case it ever grows HTML-sensitive chars
	// — today it's plain ASCII but defense-in-depth costs nothing.
	safeTitle := strings.ReplaceAll(title, "<", "&lt;")
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>%s</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@%s/swagger-ui.css">
  <style>
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@%s/swagger-ui-bundle.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@%s/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: "/docs/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [SwaggerUIBundle.plugins.DownloadUrl],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>
`, safeTitle, swaggerVersion, swaggerVersion, swaggerVersion)
}
