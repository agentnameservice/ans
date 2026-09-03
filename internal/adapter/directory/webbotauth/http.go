package webbotauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/securefetch"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// directoryContentType is the media type the web-bot-auth HTTP Message
// Signatures directory MUST be served as
// (draft-meunier-webbotauth-httpsig-protocol-02).
const directoryContentType = "application/http-message-signatures-directory+json"

// maxRedirects bounds the directory-fetch redirect chain, matching the
// did:web resolver.
const maxRedirects = 5

// HTTP is the production directory resolver: an HTTPS GET of the HTTP
// Message Signatures directory at the canonical Signature-Agent URL,
// through the shared hardened fetcher.
//
// The fetch target is registrant-steered (any host the Signature-Agent
// URL names), so SSRF is a first-class control, delegated in full to the
// securefetch toolkit (egress denylist, DNS-rebind pin, WebPKI, bounded
// redirects). Errors stay coarse — no resolved IPs, ports, or redirect
// chains reach the caller (no SSRF oracle) — and every fetch-layer
// failure is a retryable 503-class domain error, never a 500.
type HTTP struct {
	timeout      time.Duration
	maxBodyBytes int64
	rootCAs      *x509.CertPool
	allowPrivate bool
	logger       zerolog.Logger
}

// Option customizes the HTTP resolver.
type Option func(*HTTP)

// WithTimeout overrides the per-resolve hard timeout (default 5s).
func WithTimeout(d time.Duration) Option {
	return func(h *HTTP) {
		if d > 0 {
			h.timeout = d
		}
	}
}

// WithMaxBodyBytes overrides the response-size cap (default 1 MiB).
func WithMaxBodyBytes(n int64) Option {
	return func(h *HTTP) {
		if n > 0 {
			h.maxBodyBytes = n
		}
	}
}

// WithRootCAs overrides the trusted root pool (default: system roots).
// Deployments with private PKI inject their pool here; tests inject the
// httptest server's certificate.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(h *HTTP) { h.rootCAs = pool }
}

// WithAllowPrivateNetworks disables the egress IP denylist. FOR TESTS
// ONLY — it lets the full real fetch path run against a loopback TLS
// server. Never reachable from configuration.
func WithAllowPrivateNetworks() Option {
	return func(h *HTTP) { h.allowPrivate = true }
}

// WithLogger attaches a component-tagged logger (default: no-op). It
// records the failure CATEGORY (the underlying error) plus the directory
// URL and elapsed time so an on-call engineer can tell a denylist
// rejection from a DNS-rebind block, a TLS failure, a timeout, or a
// refused connection — none of which reach the API caller (the wire
// error stays coarse, no SSRF oracle).
func WithLogger(logger zerolog.Logger) Option {
	return func(h *HTTP) {
		h.logger = logger.With().Str("component", "webbotauth-directory-resolver").Logger()
	}
}

// NewHTTPResolver constructs the production directory resolver.
func NewHTTPResolver(opts ...Option) *HTTP {
	h := &HTTP{
		timeout:      5 * time.Second,
		maxBodyBytes: 1 << 20, // 1 MiB
		logger:       zerolog.Nop(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Resolve fetches and parses the directory at the canonical
// Signature-Agent URL. Hints are ignored — the resolved directory is
// always the key source.
func (h *HTTP) Resolve(ctx context.Context, directoryURL string, _ []port.KeyHint) ([]port.DirectoryKey, error) {
	u, err := url.Parse(directoryURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		// The canonical value is produced by the domain layer, so a
		// malformed URL here is an internal inconsistency, not caller
		// input; still fail retryable rather than 500.
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			"could not fetch the web-bot-auth directory")
	}
	originHost := u.Hostname()

	client := h.newClient(originHost)

	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			"could not build the directory request")
	}
	req.Header.Set("Accept", directoryContentType)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// Coarse wire error — the diagnosable category (denylist
		// rejection, DNS-rebind block, TLS failure, timeout, refused)
		// goes only to the server-side log.
		h.logger.Info().
			Err(err).
			Str("directoryUrl", directoryURL).
			Int64("elapsedMs", time.Since(start).Milliseconds()).
			Msg("web-bot-auth directory fetch failed")
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			fmt.Sprintf("could not fetch the web-bot-auth directory at %s", directoryURL))
	}
	defer func() { _ = resp.Body.Close() }()
	return h.parseResponse(directoryURL, resp)
}

// parseResponse applies the status, content-type, size, and JWKS-parse
// checks. Split from Resolve so the validation pipeline is testable
// independent of the dial/TLS plumbing.
func (h *HTTP) parseResponse(directoryURL string, resp *http.Response) ([]port.DirectoryKey, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			fmt.Sprintf("directory fetch for %s returned status %d", directoryURL, resp.StatusCode))
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		!strings.EqualFold(mediaType, directoryContentType) {
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			fmt.Sprintf("directory for %s has an unexpected content type", directoryURL))
	}
	body, err := securefetch.ReadCappedBody(resp.Body, h.maxBodyBytes)
	if err != nil {
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			fmt.Sprintf("could not read the directory for %s", directoryURL))
	}
	return parseDirectory(body)
}

// newClient builds the per-resolve HTTP client on the shared securefetch
// toolkit: the SSRF-hardened dialer (no fixed port — a Signature-Agent
// URL may carry one) + WebPKI transport + a redirect policy pinned to
// the directory host's registrable domain (or, for a host with none —
// an IP literal, as in tests — the exact host). A fresh client per call
// keeps the DNS pin scoped to one verify-control round.
func (h *HTTP) newClient(originHost string) *http.Client {
	var dialerOpts []securefetch.DialerOption
	if h.allowPrivate {
		dialerOpts = append(dialerOpts, securefetch.WithAllowPrivateNetworks())
	}
	dialer := securefetch.NewDialer(dialerOpts...)

	anchorDomain, hasRegDomain := "", false
	if d, err := securefetch.RegistrableDomain(originHost); err == nil {
		anchorDomain, hasRegDomain = d, true
	}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
				"too many redirects fetching the directory")
		}
		if req.URL.Scheme != "https" {
			return domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
				"directory redirect left https")
		}
		if hasRegDomain {
			rd, err := securefetch.RegistrableDomain(req.URL.Hostname())
			if err != nil || rd != anchorDomain {
				return domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
					"directory redirect left the directory's registrable domain")
			}
			return nil
		}
		if !strings.EqualFold(req.URL.Hostname(), originHost) {
			return domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
				"directory redirect left the directory host")
		}
		return nil
	}
	return securefetch.NewClient(dialer, h.rootCAs, checkRedirect)
}

// directoryWire is the JWKS shape the directory serves: a keys array of
// raw JWK objects. Each entry is kept raw so its exact bytes can be
// quoted verbatim into a seal.
type directoryWire struct {
	Keys []json.RawMessage `json:"keys"`
}

// keyWindow reads the optional per-key validity window
// (draft-meunier-webbotauth-httpsig-protocol-02): nbf/exp are unix-second
// JWK members. Absent members leave the corresponding bound unset.
type keyWindow struct {
	NotBefore *int64 `json:"nbf"`
	NotAfter  *int64 `json:"exp"`
}

// parseDirectory materializes the DirectoryKey set from raw JWKS bytes.
// Malformed JSON is a retryable failure (the remote is misconfigured); an
// empty or missing keys array yields an empty set (the verifier then
// rejects for "no matched key"). Each key's raw bytes are preserved for
// verbatim sealing.
func parseDirectory(body []byte) ([]port.DirectoryKey, error) {
	var wire directoryWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE",
			"directory is not valid JSON")
	}
	keys := make([]port.DirectoryKey, 0, len(wire.Keys))
	for _, raw := range wire.Keys {
		var w keyWindow
		// A key whose window members are malformed is treated as
		// unbounded rather than dropped — the thumbprint match and the
		// signature check remain the load-bearing gates.
		_ = json.Unmarshal(raw, &w)
		dk := port.DirectoryKey{JWK: raw}
		if w.NotBefore != nil {
			dk.NotBefore = time.Unix(*w.NotBefore, 0).UTC()
		}
		if w.NotAfter != nil {
			dk.NotAfter = time.Unix(*w.NotAfter, 0).UTC()
		}
		keys = append(keys, dk)
	}
	return keys, nil
}

// compile-time conformance.
var _ port.WebBotAuthDirectoryResolver = (*HTTP)(nil)
