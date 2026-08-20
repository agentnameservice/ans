package didresolver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/securefetch"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// Web is the production did:web resolver: an HTTPS GET of the DID
// document at the DID's resolution URL, through one hardened fetcher.
//
// The fetch target is registrant-steered (any host the DID names), so
// SSRF is a first-class control (design §3.7):
//
//  1. Egress IP denylist enforced at connect time, post-DNS: RFC
//     1918, loopback, link-local (which covers cloud metadata
//     addresses), ULA, and unspecified addresses are rejected at the
//     dialer, never by hostname string inspection.
//  2. The resolved IP is pinned per host for the duration of one
//     Resolve call — a DNS rebind between redirect hops cannot slip
//     an internal target past check 1.
//  3. Full WebPKI validation (chain to a trusted root + hostname
//     verification) on every fetch — Go's default TLS behavior, left
//     fully enabled.
//  4. Bounded: hard timeout (default 5 s, parity with the DNS
//     verifier), response-size cap (default 1 MiB), ≤5 redirects
//     constrained to the original host's registrable domain.
//  5. Error details never echo resolved IPs, ports, or redirect
//     chains (no SSRF oracle).
type Web struct {
	timeout      time.Duration
	maxBodyBytes int64
	rootCAs      *x509.CertPool
	allowPrivate bool
	logger       zerolog.Logger
}

// WebOption customizes the Web resolver.
type WebOption func(*Web)

// WithTimeout overrides the per-resolve hard timeout (default 5s).
func WithTimeout(d time.Duration) WebOption {
	return func(w *Web) {
		if d > 0 {
			w.timeout = d
		}
	}
}

// WithMaxBodyBytes overrides the response-size cap (default 1 MiB).
func WithMaxBodyBytes(n int64) WebOption {
	return func(w *Web) {
		if n > 0 {
			w.maxBodyBytes = n
		}
	}
}

// WithRootCAs overrides the trusted root pool (default: system
// roots). Deployments with private PKI inject their pool here; tests
// inject the httptest server's certificate.
func WithRootCAs(pool *x509.CertPool) WebOption {
	return func(w *Web) { w.rootCAs = pool }
}

// WithAllowPrivateNetworks disables the egress IP denylist. FOR
// TESTS ONLY — it exists so the full real fetch path (dialer
// included) is exercisable against a loopback TLS server. Never
// reachable from configuration.
func WithAllowPrivateNetworks() WebOption {
	return func(w *Web) { w.allowPrivate = true }
}

// WithLogger attaches a server-side logger (default: no-op). It
// records the failure CATEGORY (the underlying error) plus the DID
// and elapsed time so an on-call engineer can distinguish a
// denylist rejection from a DNS-rebind block, a TLS failure, a
// timeout, or a refused connection — none of which ever reach the
// API caller (the wire error stays deliberately coarse, no SSRF
// oracle).
func WithLogger(logger zerolog.Logger) WebOption {
	return func(w *Web) {
		w.logger = logger.With().Str("component", "did-web-resolver").Logger()
	}
}

// NewWebResolver constructs the production resolver.
func NewWebResolver(opts ...WebOption) *Web {
	w := &Web{
		timeout:      5 * time.Second,
		maxBodyBytes: 1 << 20, // 1 MiB
		logger:       zerolog.Nop(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// maxRedirects bounds the redirect chain per design §3.6.
const maxRedirects = 5

// Resolve fetches and parses the DID document. Hints are ignored —
// the authoritatively resolved document is always the key source.
func (w *Web) Resolve(ctx context.Context, did string, _ []port.KeyHint) (*port.DIDDocument, error) {
	resolutionURL, err := domain.DIDWebResolutionURL(did)
	if err != nil {
		return nil, err
	}
	originHost := strings.Split(strings.TrimPrefix(did, "did:web:"), ":")[0]

	client, err := w.newClient(originHost)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolutionURL, nil)
	if err != nil {
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED", "could not build resolution request")
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// The wire error stays deliberately coarse — no resolved IPs,
		// ports, or redirect targets (no SSRF oracle). The underlying
		// err carries the diagnosable category (denylist rejection,
		// DNS-rebind block, TLS failure, timeout, refused) and goes
		// only to the server-side log.
		w.logger.Info().
			Err(err).
			Str("did", did).
			Int64("elapsedMs", time.Since(start).Milliseconds()).
			Msg("did:web resolution fetch failed")
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED",
			fmt.Sprintf("could not fetch the DID document for %s", did))
	}
	defer func() { _ = resp.Body.Close() }()
	return w.parseResponse(did, resp)
}

// parseResponse applies the status, size, JSON, and document-id
// checks to a fetched response. Split from Resolve so the validation
// pipeline is testable independent of the dial/TLS plumbing.
func (w *Web) parseResponse(did string, resp *http.Response) (*port.DIDDocument, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED",
			fmt.Sprintf("DID document fetch for %s returned status %d", did, resp.StatusCode))
	}
	body, err := securefetch.ReadCappedBody(resp.Body, w.maxBodyBytes)
	if errors.Is(err, securefetch.ErrBodyTooLarge) {
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED",
			fmt.Sprintf("DID document for %s exceeds the %d-byte limit", did, w.maxBodyBytes))
	}
	if err != nil {
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED",
			fmt.Sprintf("could not read the DID document for %s", did))
	}

	doc, err := parseDIDDocument(body)
	if err != nil {
		return nil, err
	}
	if doc.ID != did {
		return nil, domain.NewValidationError("DID_DOCUMENT_ID_MISMATCH",
			fmt.Sprintf("DID document id %q does not match the requested DID %q", doc.ID, did))
	}
	return doc, nil
}

// newClient builds the per-resolve HTTP client on the shared
// securefetch toolkit: the SSRF-hardened pinning dialer (pinned to 443,
// the only port did:web can express) + WebPKI transport +
// same-registrable-domain redirect policy. A fresh client per call
// keeps the DNS pin scoped to exactly one verify-control round.
func (w *Web) newClient(originHost string) (*http.Client, error) {
	dialerOpts := []securefetch.DialerOption{securefetch.WithRequirePort("443")}
	if w.allowPrivate {
		dialerOpts = append(dialerOpts, securefetch.WithAllowPrivateNetworks())
	}
	dialer := securefetch.NewDialer(dialerOpts...)

	originDomain, err := securefetch.RegistrableDomain(originHost)
	if err != nil {
		return nil, domain.NewValidationError("DID_BAD_FORMAT",
			fmt.Sprintf("did:web host %q has no registrable domain", originHost))
	}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return domain.NewValidationError("DID_RESOLUTION_FAILED",
				"too many redirects resolving the DID document")
		}
		if req.URL.Scheme != "https" {
			return domain.NewValidationError("DID_RESOLUTION_FAILED",
				"DID document redirect left https")
		}
		redirDomain, derr := securefetch.RegistrableDomain(req.URL.Hostname())
		if derr != nil || redirDomain != originDomain {
			return domain.NewValidationError("DID_REDIRECT_DOMAIN_MISMATCH",
				"DID document redirect left the DID's registrable domain")
		}
		return nil
	}
	return securefetch.NewClient(dialer, w.rootCAs, checkRedirect), nil
}

// didDocumentWire is the on-the-wire DID document subset we parse.
// Both arrays are kept as raw JSON: verificationMethod entries so
// the EXACT served bytes can be quoted verbatim into seals,
// assertionMethod entries because they are either string references
// or inline verification-method objects.
type didDocumentWire struct {
	ID                 string            `json:"id"`
	VerificationMethod []json.RawMessage `json:"verificationMethod"`
	AssertionMethod    []json.RawMessage `json:"assertionMethod"`
}

type vmWire struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Controller         string          `json:"controller"`
	PublicKeyJwk       json.RawMessage `json:"publicKeyJwk"`
	PublicKeyMultibase string          `json:"publicKeyMultibase"`
}

func (v vmWire) toPort(raw json.RawMessage) port.VerificationMethod {
	return port.VerificationMethod{
		ID:                 v.ID,
		Controller:         v.Controller,
		Type:               v.Type,
		PublicKeyJwk:       v.PublicKeyJwk,
		PublicKeyMultibase: v.PublicKeyMultibase,
		Raw:                raw,
	}
}

// parseDIDDocument builds the port.DIDDocument from raw did.json
// bytes, materializing the assertionMethod set: string entries
// dereference into verificationMethod; object entries are used
// inline. Every entry carries its Raw bytes — the document's own
// JSON for that method, which is what sealing quotes.
func parseDIDDocument(body []byte) (*port.DIDDocument, error) {
	var wire didDocumentWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, domain.NewValidationError("DID_RESOLUTION_FAILED",
			"DID document is not valid JSON")
	}
	byID := make(map[string]port.VerificationMethod, len(wire.VerificationMethod))
	for _, raw := range wire.VerificationMethod {
		var vm vmWire
		if err := json.Unmarshal(raw, &vm); err == nil && vm.ID != "" {
			byID[vm.ID] = vm.toPort(raw)
		}
	}
	doc := &port.DIDDocument{ID: wire.ID}
	for _, raw := range wire.AssertionMethod {
		var ref string
		if err := json.Unmarshal(raw, &ref); err == nil {
			if vm, ok := byID[ref]; ok {
				doc.AssertionMethod = append(doc.AssertionMethod, vm)
			}
			continue
		}
		var vm vmWire
		if err := json.Unmarshal(raw, &vm); err == nil && vm.ID != "" {
			doc.AssertionMethod = append(doc.AssertionMethod, vm.toPort(raw))
		}
	}
	return doc, nil
}

// compile-time conformance.
var _ port.DIDResolver = (*Web)(nil)
