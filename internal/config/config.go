// Package config loads and validates runtime configuration for ans-ra
// and ans-tl from YAML files with environment variable overrides.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Server holds HTTP server settings.
type Server struct {
	Host string `koanf:"host"`
	Port int    `koanf:"port"`
}

// Auth holds authentication provider configuration.
type Auth struct {
	// Type selects the adapter: "static" or "oidc".
	Type       string      `koanf:"type"`
	Static     *AuthStatic `koanf:"static"`
	OIDC       *AuthOIDC   `koanf:"oidc"`
	PublicRead bool        `koanf:"public-read"` // TL only — allow unauthenticated reads.
}

// AuthStatic configures the static API-key adapter.
//
// `APIKey` is always required. `APISecret` is optional:
//
//   - When both are set, the server accepts the reference RA's
//     `Authorization: sso-key <apiKey>:<apiSecret>` header format in
//     addition to the Bearer format. This is the format the ANS SDKs
//     send, so SDK-based tests require the secret to be configured.
//
//   - When only APIKey is set, the server accepts only
//     `Authorization: Bearer <apiKey>`. Good for local curl-based
//     tooling, but SDK-generated clients will not authenticate.
type AuthStatic struct {
	APIKey    string `koanf:"api-key"`
	APISecret string `koanf:"api-secret"`
}

// AuthOIDC configures the OIDC adapter.
//
// AdminGroups is the list of group names — matched against the
// authenticated token's `groups` claim — whose members should be
// treated as administrators (`Identity.IsAdmin == true`). Empty or
// unset means no OIDC user is an admin, which leaves any admin-only
// route (e.g., the TL's /internal/v1/producer-keys family) closed
// to all OIDC traffic. Static auth grants admin unconditionally;
// only the OIDC path needs this list.
type AuthOIDC struct {
	IssuerURL   string   `koanf:"issuer-url"`
	Audience    string   `koanf:"audience"`
	ClientID    string   `koanf:"client-id"`
	AdminGroups []string `koanf:"admin-groups"`
}

// CA holds identity certificate authority settings.
//
// `Server` is optional: when non-nil it configures the server
// certificate issuer used for server CSRs submitted at registration
// or renewal. When nil, the RA only supports the BYOC path for
// server certs. The identity CA (`Self`) is always required — every
// agent gets an RA-issued identity cert.
type CA struct {
	Type   string    `koanf:"type"`
	Self   *CASelf   `koanf:"self"`
	Server *CAServer `koanf:"server"`
}

// CASelf configures the in-process self-signed identity CA.
type CASelf struct {
	Org          string `koanf:"org"`
	ValidityDays int    `koanf:"validity-days"`
	DataDir      string `koanf:"data-dir"`
}

// CAServer selects and configures the server certificate issuer
// behind `port.ServerCertificateIssuer`.
//
//   - Type "self" (default, including when omitted — backwards
//     compatible with pre-issuer configs): the in-process
//     self-signed server CA. Same shape as the identity CA but kept
//     distinct so operators can rotate the two roots independently.
//   - Type "acme": an external RFC 8555 CA (Let's Encrypt et al.)
//     configured by the nested `acme` block. Selecting this type is
//     the operator's consent to the provider's terms of service —
//     account registration auto-accepts them, per standard ACME
//     automation practice.
type CAServer struct {
	Type string `koanf:"type"`

	// Self-signed issuer settings (type "self").
	Org          string `koanf:"org"`
	ValidityDays int    `koanf:"validity-days"`
	DataDir      string `koanf:"data-dir"`

	// ACME issuer settings (type "acme").
	ACME *CAServerACME `koanf:"acme"`
}

// IsACME reports whether the server issuer is the ACME adapter.
func (s *CAServer) IsACME() bool { return s != nil && s.Type == "acme" }

// CAServerACME configures the RFC 8555 issuer.
type CAServerACME struct {
	// DirectoryURL is the provider's directory endpoint, e.g.
	// https://acme-staging-v02.api.letsencrypt.org/directory for
	// Let's Encrypt staging. Use staging for testing — production
	// rate limits are unforgiving.
	DirectoryURL string `koanf:"directory-url"`
	// Email becomes the ACME account contact for expiry and incident
	// notices. Optional.
	Email string `koanf:"email"`
	// DataDir persists the ACME account key across restarts.
	DataDir string `koanf:"data-dir"`
}

// DNS holds DNS verifier configuration.
type DNS struct {
	// Type selects the verifier adapter. "noop" accepts any DNS
	// state; "lookup" queries a real nameserver via miekg/dns and
	// validates TXT, TLSA, and HTTPS records, surfacing the DNSSEC
	// AuthenticatedData bit on TLSA responses.
	Type string `koanf:"type"` // "noop" | "lookup"

	// Server is an optional "host:port" override for the nameserver
	// the "lookup" verifier queries. When empty the system resolver
	// (/etc/resolv.conf) is used. Point at the local `ans-dns` dev
	// server (e.g. "127.0.0.1:15353") for self-contained local
	// testing.
	Server string `koanf:"server"`
}

// Identity holds Verified Identity (the "who") configuration — the
// /v2/ans/identities surface (RA only).
type Identity struct {
	// Resolver selects the did:web document fetcher.
	Resolver IdentityResolver `koanf:"resolver"`
	// ChallengeTTL bounds the verify-control nonce (default 1h; 5m
	// is the design floor for high-assurance deployments).
	ChallengeTTL time.Duration `koanf:"challenge-ttl"`
	// RegisterRateLimit is the per-owner register/rotate budget per
	// minute (default 10) — each call can trigger an outbound
	// did:web fetch before any proof exists.
	RegisterRateLimit int `koanf:"register-rate-limit"`
	// LinkRateLimit is the per-owner link/unlink budget per minute
	// (default 60) — operational hardening on the link route
	// (design §4.3).
	LinkRateLimit int `koanf:"link-rate-limit"`
	// SealTimeout bounds the inline TL seal call identity operations
	// make before reporting success (seal-before-success, design
	// §5.6.1). Default 5s.
	SealTimeout time.Duration `koanf:"seal-timeout"`
}

// IdentityResolver selects the did:web resolver adapter. "noop"
// performs no I/O and synthesizes the DID document from the keys
// embedded in the submitted proofs (quickstart — signature
// verification still genuinely runs, only the live-document binding
// is waived; NOT for production); "web" performs the hardened HTTPS
// fetch with WebPKI validation and SSRF dialer guards.
type IdentityResolver struct {
	Type string `koanf:"type"` // "noop" | "web"
}

// VLEI selects the vLEI (lei kind) control verifier — the GLEIF /
// vlei-verifier interaction behind the lei identifier kind. Top-level,
// matching the DNS verifier's placement (not nested under identity),
// because it is a distinct outbound dependency with its own service
// endpoint.
//
// "noop" runs real Ed25519 crypto over the signing input but waives
// the GLEIF authorization binding (quickstart — NOT for production);
// "verifier" is a hardened HTTP client for an internal vlei-verifier
// service.
type VLEI struct {
	Type string `koanf:"type"` // "noop" | "verifier"
	// BaseURL is the internal vlei-verifier service URL, required when
	// type is "verifier" (e.g. "http://vlei-verifier:7676").
	BaseURL string `koanf:"base-url"`
	// PresentTimeout bounds each verifier HTTP request (default 5s).
	PresentTimeout time.Duration `koanf:"present-timeout"`
}

// Keys holds key-manager configuration.
type Keys struct {
	Type string    `koanf:"type"` // "file"
	File *KeysFile `koanf:"file"`
}

// KeysFile configures the filesystem key manager.
type KeysFile struct {
	Path string `koanf:"path"`
}

// Store holds persistence adapter configuration.
type Store struct {
	Type   string       `koanf:"type"` // "sqlite"
	SQLite *StoreSQLite `koanf:"sqlite"`
}

// StoreSQLite configures the SQLite store.
type StoreSQLite struct {
	Path string `koanf:"path"`
}

// TLClient holds RA→TL HTTP client and outbox-worker configuration
// (RA only).
//
// The outbox worker runs as a background goroutine in ans-ra. It
// claims batches of pending events from the outbox table, POSTs each
// to the TL, and marks them sent or failed. Failed rows are retried
// with capped exponential backoff.
type TLClient struct {
	// BaseURL is the TL's listen URL, e.g. "http://localhost:18081".
	BaseURL string `koanf:"base-url"`
	// PublicBaseURL is the TL's externally-reachable URL used in
	// _ans-badge DNS TXT records. Required — must be an https:// URL
	// with no query string, fragment, or userinfo.
	PublicBaseURL string `koanf:"public-base-url"`
	// APIKey is the bearer token the TL's static auth accepts.
	APIKey string `koanf:"api-key"`
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration `koanf:"timeout"`
	// BatchSize is how many outbox rows each worker tick claims at
	// once. Larger batches reduce DB roundtrips but delay shutdown.
	BatchSize int `koanf:"batch-size"`
	// PollInterval is how often the worker polls the outbox for
	// newly-enqueued events.
	PollInterval time.Duration `koanf:"poll-interval"`
	// MaxBackoff caps the per-row exponential backoff on failure.
	// A permanently-broken event re-enters the claim list at this
	// cadence.
	MaxBackoff time.Duration `koanf:"max-backoff"`
	// Disabled turns the worker off entirely. Events still accumulate
	// in the outbox; useful for tests and for operators who want to
	// run the worker as a separate process.
	Disabled bool `koanf:"disabled"`
}

// Merkle holds Transparency Log Merkle tree configuration (TL only).
type Merkle struct {
	Origin             string        `koanf:"origin"`
	TileStorage        TileStorage   `koanf:"tile-storage"`
	CheckpointInterval time.Duration `koanf:"checkpoint-interval"`
}

// TileStorage configures Merkle tile storage (TL only).
type TileStorage struct {
	Type       string                 `koanf:"type"` // "filesystem"
	Filesystem *TileStorageFilesystem `koanf:"filesystem"`
}

// TileStorageFilesystem configures filesystem tile storage.
type TileStorageFilesystem struct {
	Path string `koanf:"path"`
}

// Log holds logging configuration.
type Log struct {
	Level  string `koanf:"level"`  // trace|debug|info|warn|error
	Format string `koanf:"format"` // "text" | "json"
}

// RAConfig is the full configuration for ans-ra.
type RAConfig struct {
	Server   Server    `koanf:"server"`
	Auth     Auth      `koanf:"auth"`
	CA       CA        `koanf:"ca"`
	DNS      DNS       `koanf:"dns"`
	Identity Identity  `koanf:"identity"`
	VLEI     VLEI      `koanf:"vlei"`
	Keys     Keys      `koanf:"keys"`
	Store    Store     `koanf:"store"`
	TLClient TLClient  `koanf:"tl-client"`
	Signer   SignerCfg `koanf:"signer"`
	Log      Log       `koanf:"log"`
}

// SignerCfg names the KeyManager-managed key the RA uses to sign
// outbox events before they're POSTed to the TL. The RaID identifies
// this RA instance to the TL's producer-key trust store.
type SignerCfg struct {
	KeyID string `koanf:"keyId"`
	RaID  string `koanf:"raId"`
}

// TLConfig is the full configuration for ans-tl.
type TLConfig struct {
	Server       Server            `koanf:"server"`
	Auth         Auth              `koanf:"auth"`
	Keys         Keys              `koanf:"keys"`
	Store        Store             `koanf:"store"`
	Merkle       Merkle            `koanf:"merkle"`
	Attestation  AttestationKeyCfg `koanf:"attestation"`
	StatusToken  StatusTokenCfg    `koanf:"statusToken"`
	ProducerKeys []ProducerKeyCfg  `koanf:"producerKeys"`
	Log          Log               `koanf:"log"`
}

// AttestationKeyCfg names the KeyManager-managed key the TL uses for
// every outbound signature: primary C2SP checkpoint signature, JWS
// additional-signer line, outer envelope attestation, SCITT
// receipts, and status tokens. Single-key topology matching the
// reference TL's deployed shape.
type AttestationKeyCfg struct {
	// KeyID is looked up in the KeyManager. Auto-provisioned on first
	// run at EnsureKey time with the ECDSA_P256 algorithm.
	KeyID string `koanf:"keyId"`
}

// StatusTokenCfg controls the /v1/agents/{id}/status-token endpoint.
//
// `ttl` defaults to 1h when zero; shorter TTLs tighten revocation
// propagation at the cost of more AHP↔TL traffic. The signing key is
// the single TL signing key declared under `attestation.keyId`;
// status-token rotation is tied to the log's signing-key lifecycle.
type StatusTokenCfg struct {
	TTL time.Duration `koanf:"ttl"`
}

// ProducerKeyCfg is one trusted RA public key as declared in config.
// Stage 1 ships this as the sole source of producer trust; Stage 3
// swaps it for a SQLite store with admin-routed CRUD.
type ProducerKeyCfg struct {
	RaID         string `koanf:"raId"`
	KeyID        string `koanf:"keyId"`
	Algorithm    string `koanf:"algorithm"`
	PublicKeyPEM string `koanf:"publicKeyPem"`
}

// LoadRA loads and validates ans-ra configuration from the given YAML path.
// Environment variables prefixed with ANS_RA_ override file values;
// nested keys use double underscores (ANS_RA_AUTH__STATIC__API_KEY).
func LoadRA(path string) (*RAConfig, error) {
	k, err := loadKoanf(path, "ANS_RA_")
	if err != nil {
		return nil, err
	}
	cfg := defaultRAConfig()
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// LoadTL loads and validates ans-tl configuration from the given YAML path.
func LoadTL(path string) (*TLConfig, error) {
	k, err := loadKoanf(path, "ANS_TL_")
	if err != nil {
		return nil, err
	}
	cfg := defaultTLConfig()
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

func loadKoanf(path, envPrefix string) (*koanf.Koanf, error) {
	k := koanf.New(".")
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: load %s: %w", path, err)
		}
	}
	// Environment overrides: ANS_RA_SERVER__PORT -> server.port
	envProvider := env.Provider(envPrefix, ".", func(s string) string {
		return strings.ReplaceAll(
			strings.ToLower(strings.TrimPrefix(s, envPrefix)),
			"__", ".",
		)
	})
	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("config: load env: %w", err)
	}
	return k, nil
}

// Validate ensures the RA config is internally consistent.
func (c *RAConfig) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port out of range: %d", c.Server.Port)
	}
	if err := validateAuth(&c.Auth); err != nil {
		return err
	}
	if c.CA.Type != "self" {
		return fmt.Errorf("ca.type %q not supported (expected 'self')", c.CA.Type)
	}
	if c.CA.Self == nil || c.CA.Self.DataDir == "" {
		return errors.New("ca.self.data-dir is required")
	}
	if c.CA.Self.ValidityDays <= 0 {
		return errors.New("ca.self.validity-days must be positive")
	}
	// Server issuer is optional but when configured must be valid.
	if err := validateCAServer(c.CA.Server); err != nil {
		return err
	}
	switch c.DNS.Type {
	case "noop", "lookup":
	default:
		return fmt.Errorf("dns.type %q not supported (expected 'noop' or 'lookup')", c.DNS.Type)
	}
	// An ACME server issuer with the noop DNS verifier is a footgun:
	// the noop gate "passes" every challenge, so the RA would answer
	// the public provider's challenge before the owner published the
	// artifact, and the provider would mark the authorization (and the
	// order) invalid. A real provider needs the real lookup verifier.
	if c.CA.Server.IsACME() && c.DNS.Type == "noop" {
		return errors.New(
			"ca.server.type 'acme' requires dns.type 'lookup': a noop challenge gate would answer the provider's challenge before the artifact exists and invalidate every order")
	}
	switch c.Identity.Resolver.Type {
	case "noop", "web":
	default:
		return fmt.Errorf("identity.resolver.type %q not supported (expected 'noop' or 'web')", c.Identity.Resolver.Type)
	}
	if c.Identity.ChallengeTTL < 0 {
		return errors.New("identity.challenge-ttl must not be negative")
	}
	if c.Identity.RegisterRateLimit < 0 {
		return errors.New("identity.register-rate-limit must not be negative")
	}
	if err := validateVLEI(&c.VLEI); err != nil {
		return err
	}
	if err := validateKeys(&c.Keys); err != nil {
		return err
	}
	if err := validateStore(&c.Store); err != nil {
		return err
	}
	if c.TLClient.BaseURL == "" {
		return errors.New("tl-client.base-url is required")
	}
	if err := validatePublicBaseURL(c.TLClient.PublicBaseURL); err != nil {
		return err
	}
	if c.TLClient.Timeout <= 0 {
		c.TLClient.Timeout = 10 * time.Second
	}
	return nil
}

// Validate ensures the TL config is internally consistent.
func (c *TLConfig) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port out of range: %d", c.Server.Port)
	}
	if err := validateAuth(&c.Auth); err != nil {
		return err
	}
	if err := validateKeys(&c.Keys); err != nil {
		return err
	}
	if err := validateStore(&c.Store); err != nil {
		return err
	}
	if c.Merkle.Origin == "" {
		return errors.New("merkle.origin is required")
	}
	if c.Merkle.TileStorage.Type != "filesystem" {
		return fmt.Errorf("merkle.tile-storage.type %q not supported", c.Merkle.TileStorage.Type)
	}
	if c.Merkle.TileStorage.Filesystem == nil || c.Merkle.TileStorage.Filesystem.Path == "" {
		return errors.New("merkle.tile-storage.filesystem.path is required")
	}
	if c.Merkle.CheckpointInterval <= 0 {
		c.Merkle.CheckpointInterval = 10 * time.Second
	}
	return nil
}

// validateCAServer checks the optional server-issuer block. Nil is
// valid (BYOC-only deployment).
func validateCAServer(s *CAServer) error {
	if s == nil {
		return nil
	}
	switch s.Type {
	case "", "self":
		if s.DataDir == "" {
			return errors.New("ca.server.data-dir is required when ca.server block is set")
		}
		if s.ValidityDays <= 0 {
			return errors.New("ca.server.validity-days must be positive")
		}
	case "acme":
		if s.ACME == nil {
			return errors.New("ca.server.acme block is required when ca.server.type is 'acme'")
		}
		if s.ACME.DirectoryURL == "" {
			return errors.New("ca.server.acme.directory-url is required")
		}
		if s.ACME.DataDir == "" {
			return errors.New("ca.server.acme.data-dir is required")
		}
	default:
		return fmt.Errorf("ca.server.type %q not supported (expected 'self' or 'acme')", s.Type)
	}
	return nil
}

// validateVLEI checks the vLEI control-verifier selection: "noop"
// needs nothing, "verifier" needs a valid http(s) base URL, and the
// per-request timeout may not be negative.
func validateVLEI(v *VLEI) error {
	switch v.Type {
	case "noop":
	case "verifier":
		if v.BaseURL == "" {
			return errors.New("vlei.base-url is required when vlei.type is 'verifier'")
		}
		u, err := url.Parse(v.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("vlei.base-url must be a valid http(s) URL, got %q", v.BaseURL)
		}
	default:
		return fmt.Errorf("vlei.type %q not supported (expected 'noop' or 'verifier')", v.Type)
	}
	if v.PresentTimeout < 0 {
		return errors.New("vlei.present-timeout must not be negative")
	}
	return nil
}

func validateAuth(a *Auth) error {
	switch a.Type {
	case "static":
		if a.Static == nil || a.Static.APIKey == "" {
			return errors.New("auth.static.api-key required when auth.type is 'static'")
		}
	case "oidc":
		if a.OIDC == nil || a.OIDC.IssuerURL == "" || a.OIDC.Audience == "" {
			return errors.New("auth.oidc.issuer-url and audience required when auth.type is 'oidc'")
		}
	default:
		return fmt.Errorf("auth.type %q not supported (expected 'static' or 'oidc')", a.Type)
	}
	return nil
}

func validateKeys(k *Keys) error {
	if k.Type != "file" {
		return fmt.Errorf("keys.type %q not supported (expected 'file')", k.Type)
	}
	if k.File == nil || k.File.Path == "" {
		return errors.New("keys.file.path is required")
	}
	return nil
}

func validateStore(s *Store) error {
	if s.Type != "sqlite" {
		return fmt.Errorf("store.type %q not supported (expected 'sqlite')", s.Type)
	}
	if s.SQLite == nil || s.SQLite.Path == "" {
		return errors.New("store.sqlite.path is required")
	}
	return nil
}

func validatePublicBaseURL(raw string) error {
	if raw == "" {
		return errors.New("tl-client.public-base-url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("tl-client.public-base-url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("tl-client.public-base-url must use https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("tl-client.public-base-url: missing host")
	}
	if u.User != nil {
		return errors.New("tl-client.public-base-url: userinfo not allowed")
	}
	if u.RawQuery != "" {
		return errors.New("tl-client.public-base-url: query string not allowed")
	}
	if u.Fragment != "" {
		return errors.New("tl-client.public-base-url: fragment not allowed")
	}
	return nil
}
