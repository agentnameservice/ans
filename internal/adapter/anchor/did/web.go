// Package did implements the ANS-0 §0.B DID anchor profile.
//
// The package's first concrete profile is did:web, which is also
// the priority sub-profile per docs/profiles/anchor-0b-did.md §1.
// Other DID methods (did:plc, did:key, did:ethr/did:pkh, did:ion)
// will land as additional Resolver implementations in this package
// once the did:web shape is proven and the SDK + CLI surface lands.
package did

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// WebProfileID is the canonical identifier for the did:web profile.
const WebProfileID = "0.B-did:web"

// freshnessBudget is the maximum age of a cached resolution for
// did:web before the resolver MUST re-resolve. Matches the budget
// recommended in docs/profiles/anchor-0b-did.md §3.5.
const freshnessBudget = 24 * time.Hour

// Web resolves did:web identifiers by fetching the published DID
// document over HTTPS, validating it against the W3C DID Core
// requirements, selecting the active verification method, and
// shaping an IdentityClaim. Resolution semantics follow
// docs/profiles/anchor-0b-did.md §3.
//
// The resolver is deliberately stateless. A caller wiring rate
// limits, response caching, or HTTP-client tuning configures the
// http.Client passed in via WithHTTPClient. The resolver's verbatim
// fetch + validate + shape pipeline is short enough to keep in one
// place; future profiles share the JWK conversion and verification-
// method selection helpers but each owns its own resolution call.
type Web struct {
	client *http.Client
	clock  func() time.Time
}

// NewWeb constructs a Web resolver with sensible defaults: a 10s
// timeout HTTP client, follow up to 5 redirects (validated below
// for cross-domain rejection), reject TLS below 1.2 implicitly via
// the standard library defaults.
func NewWeb() *Web {
	return &Web{
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: webRedirectPolicy,
		},
		clock: time.Now,
	}
}

// WithHTTPClient returns a copy of the resolver using the provided
// http.Client. Tests inject a client whose Transport routes to an
// httptest.Server so the resolver hits a stable known target.
func (w *Web) WithHTTPClient(c *http.Client) *Web {
	return &Web{client: c, clock: w.clock}
}

// WithClock returns a copy of the resolver with a deterministic
// clock. Tests use this so IssuedAt is reproducible.
func (w *Web) WithClock(clock func() time.Time) *Web {
	return &Web{client: w.client, clock: clock}
}

// SupportedProfiles satisfies port.AnchorResolver.
func (w *Web) SupportedProfiles() []string {
	return []string{WebProfileID}
}

// Resolve implements port.AnchorResolver for did:web. The pipeline
// matches anchor-0b-did.md §3.2:
//
//  1. Lexical validation (DID URI shape, did:web method).
//  2. Construct the resolution URL per the path-component mapping.
//  3. HTTPS GET with Accept: application/did+json, application/json.
//  4. Validate response status, content type.
//  5. Parse as DID document; validate id field.
//  6. Select active verification method (assertionMethod first).
//  7. Convert verification method's public key to JWK form.
//  8. Construct IdentityClaim with IssuedAt = now.
func (w *Web) Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error) {
	domainPart, pathComponents, err := parseDIDWeb(input)
	if err != nil {
		return nil, err
	}

	resolutionURL := buildResolutionURL(domainPart, pathComponents)

	doc, err := w.fetchDIDDocument(ctx, resolutionURL)
	if err != nil {
		return nil, err
	}

	canonicalDID := canonicalizeDID(domainPart, pathComponents)
	if !strings.EqualFold(doc.ID, canonicalDID) {
		return nil, domain.NewValidationError(
			"DID_DOCUMENT_ID_MISMATCH",
			fmt.Sprintf("DID document id %q does not match resolved DID %q", doc.ID, canonicalDID),
		)
	}

	jwk, err := selectVerificationMethodJWK(doc)
	if err != nil {
		return nil, err
	}

	now := w.clock().UTC()
	expires := now.Add(freshnessBudget)

	return &domain.IdentityClaim{
		AnchorType:   domain.AnchorTypeDID,
		ResolvedID:   canonicalDID,
		PublicKeyJWK: jwk,
		MetadataURL:  resolutionURL,
		IssuedAt:     now,
		ExpiresAt:    expires,
	}, nil
}

// webRedirectPolicy enforces same-effective-second-level-domain
// redirects per anchor-0b-did.md §3.2 step 3. Up to 5 redirects
// allowed; any cross-domain redirect fails closed with
// DID_REDIRECT_DOMAIN_MISMATCH.
func webRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("DID_TOO_MANY_REDIRECTS: stopped after 5 redirects")
	}
	if len(via) == 0 {
		return nil
	}
	original := via[0].URL.Host
	current := req.URL.Host
	if !sameEffectiveDomain(original, current) {
		return fmt.Errorf("DID_REDIRECT_DOMAIN_MISMATCH: %s redirected to %s", original, current)
	}
	return nil
}

// sameEffectiveDomain compares two hostnames by their last two
// labels. This is a deliberately conservative same-site check; it
// does not consult the public-suffix list because that introduces a
// runtime data dependency. A future refinement can wire in the
// PSL for ccTLD-aware matching, but the current rule errors on the
// side of refusing valid co-publisher redirects rather than
// admitting cross-domain ones.
func sameEffectiveDomain(a, b string) bool {
	aParts := strings.Split(strings.ToLower(stripPort(a)), ".")
	bParts := strings.Split(strings.ToLower(stripPort(b)), ".")
	if len(aParts) < 2 || len(bParts) < 2 {
		return strings.EqualFold(a, b)
	}
	aRoot := aParts[len(aParts)-2] + "." + aParts[len(aParts)-1]
	bRoot := bParts[len(bParts)-2] + "." + bParts[len(bParts)-1]
	return aRoot == bRoot
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

// parseDIDWeb splits a did:web URI into (domain, path components).
// Returns the domain in canonical lowercase form and a slice of
// URL-decoded path components.
//
// did:web:<domain>(:<path-component>)*
//   - did:web:agent.example.com               -> ("agent.example.com", [])
//   - did:web:agent.example.com:agents:billing -> ("agent.example.com", ["agents", "billing"])
//
// Per the W3C method spec, percent-encoded colons in the domain are
// preserved as port indicators; this resolver does not yet support
// non-default ports and rejects domains carrying explicit ports
// with DID_PORT_NOT_SUPPORTED.
func parseDIDWeb(input string) (string, []string, error) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "did:web:") {
		return "", nil, domain.NewValidationError(
			"DID_BAD_FORMAT",
			"expected did:web prefix",
		)
	}
	rest := strings.TrimPrefix(trimmed, "did:web:")
	if rest == "" {
		return "", nil, domain.NewValidationError(
			"DID_BAD_FORMAT",
			"did:web URI missing identifier body",
		)
	}
	parts := strings.Split(rest, ":")
	domainPart := strings.ToLower(parts[0])
	if domainPart == "" {
		return "", nil, domain.NewValidationError(
			"DID_BAD_FORMAT",
			"did:web URI missing domain component",
		)
	}
	if strings.Contains(domainPart, "%3a") || strings.Contains(domainPart, "%3A") {
		return "", nil, domain.NewValidationError(
			"DID_PORT_NOT_SUPPORTED",
			"did:web with explicit port (percent-encoded colon) is not supported",
		)
	}
	pathComponents := make([]string, 0, len(parts)-1)
	for _, raw := range parts[1:] {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return "", nil, domain.NewValidationError(
				"DID_BAD_FORMAT",
				"did:web path component is not URL-encoded: "+raw,
			)
		}
		if decoded == "" {
			return "", nil, domain.NewValidationError(
				"DID_BAD_FORMAT",
				"did:web path component is empty (consecutive colons)",
			)
		}
		pathComponents = append(pathComponents, decoded)
	}
	return domainPart, pathComponents, nil
}

// buildResolutionURL constructs the HTTPS URL the resolver fetches
// to retrieve the DID document. Per anchor-0b-did.md §3.2 step 2:
//
//   - empty path components: https://<domain>/.well-known/did.json
//   - non-empty path components: https://<domain>/<comp1>/<comp2>/.../did.json
func buildResolutionURL(domainPart string, pathComponents []string) string {
	if len(pathComponents) == 0 {
		return "https://" + domainPart + "/.well-known/did.json"
	}
	escaped := make([]string, 0, len(pathComponents))
	for _, c := range pathComponents {
		escaped = append(escaped, url.PathEscape(c))
	}
	return "https://" + domainPart + "/" + strings.Join(escaped, "/") + "/did.json"
}

// canonicalizeDID returns the lowercase did:web URI form for the
// IdentityClaim's ResolvedID. The fragment (verification-method
// selector) is dropped per anchor-0b-did.md §2.
func canonicalizeDID(domainPart string, pathComponents []string) string {
	if len(pathComponents) == 0 {
		return "did:web:" + domainPart
	}
	escaped := make([]string, 0, len(pathComponents))
	for _, c := range pathComponents {
		escaped = append(escaped, url.PathEscape(c))
	}
	return "did:web:" + domainPart + ":" + strings.Join(escaped, ":")
}

// fetchDIDDocument issues the HTTPS GET, validates the response, and
// returns the parsed DID document.
func (w *Web) fetchDIDDocument(ctx context.Context, resolutionURL string) (*didDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolutionURL, nil)
	if err != nil {
		return nil, domain.NewInternalError(
			"DID_REQUEST_BUILD",
			"build HTTP request for did:web resolution",
			err,
		)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, domain.NewValidationError(
			"DID_RESOLUTION_FAILED",
			"HTTPS GET failed: "+err.Error(),
		)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, domain.NewValidationError(
			"DID_RESOLUTION_FAILED",
			fmt.Sprintf("HTTPS GET returned status %d", resp.StatusCode),
		)
	}

	contentType := strings.ToLower(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	contentType = strings.TrimSpace(contentType)
	if contentType != "application/did+json" && contentType != "application/json" {
		return nil, domain.NewValidationError(
			"DID_BAD_CONTENT_TYPE",
			"expected application/did+json or application/json, got "+contentType,
		)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MiB cap
	if err != nil {
		return nil, domain.NewValidationError(
			"DID_RESOLUTION_FAILED",
			"read response body: "+err.Error(),
		)
	}

	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, domain.NewValidationError(
			"DID_DOCUMENT_PARSE",
			"DID document is not valid JSON: "+err.Error(),
		)
	}
	if doc.ID == "" {
		return nil, domain.NewValidationError(
			"DID_DOCUMENT_PARSE",
			"DID document missing required id field",
		)
	}
	return &doc, nil
}

// didDocument is the minimal subset of W3C DID Core §5 fields the
// resolver needs. Adding more fields here is safe; JSON decode
// ignores anything not declared.
type didDocument struct {
	ID                 string               `json:"id"`
	VerificationMethod []verificationMethod `json:"verificationMethod,omitempty"`
	AssertionMethod    []json.RawMessage    `json:"assertionMethod,omitempty"`
	Authentication     []json.RawMessage    `json:"authentication,omitempty"`
}

type verificationMethod struct {
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Controller      string          `json:"controller"`
	PublicKeyJwk    json.RawMessage `json:"publicKeyJwk,omitempty"`
	PublicKeyMultib string          `json:"publicKeyMultibase,omitempty"`
	PublicKeyPem    string          `json:"publicKeyPem,omitempty"`
	Created         string          `json:"created,omitempty"`
	Updated         string          `json:"updated,omitempty"`
}
