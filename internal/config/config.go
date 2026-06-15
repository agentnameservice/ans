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
// `Server` is optional: when non-nil it configures an additional
// server-auth CA used to sign server CSRs submitted at registration
// or renewal. When nil, the RA only supports the BYOC path for
// server certs. The identity CA (`Self`) is always required — every
// agent gets an RA-issued identity cert.
type CA struct {
	Type   string        `koanf:"type"`
	Self   *CASelf       `koanf:"self"`
	Server *CAServerSelf `koanf:"server"`
}

// CASelf configures the in-process self-signed identity CA.
type CASelf struct {
	Org          string `koanf:"org"`
	ValidityDays int    `koanf:"validity-days"`
	DataDir      string `koanf:"data-dir"`
}

// CAServerSelf configures the in-process self-signed server CA. The
// shape matches CASelf (org + validity + data-dir); kept distinct so
// operators can rotate the identity and server roots independently.
type CAServerSelf struct {
	Org          string `koanf:"org"`
	ValidityDays int    `koanf:"validity-days"`
	DataDir      string `koanf:"data-dir"`
}

// DNS holds DNS verifier and optional provisioner configuration.
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

	// Provisioner configures automatic DNS record creation/deletion.
	// When nil or empty, operators manage DNS manually (the default).
	Provisioner *DNSProvisionerConfig `koanf:"provisioner"`
}

// DNSProvisionerConfig selects the DNS provisioning adapter.
type DNSProvisionerConfig struct {
	Type string         `koanf:"type"` // "ddns"
	DDNS *DNSDDNSConfig `koanf:"ddns"`
}

// DNSDDNSConfig holds RFC 2136 dynamic DNS update settings.
type DNSDDNSConfig struct {
	Server        string        `koanf:"server"`         // "host:port" of authoritative nameserver
	Zone          string        `koanf:"zone"`           // zone name (FQDN, e.g. "obispo.link.")
	TSIGName      string        `koanf:"tsig-name"`      // TSIG key name (FQDN)
	TSIGSecret    string        `koanf:"tsig-secret"`    // base64-encoded shared secret
	TSIGAlgorithm string        `koanf:"tsig-algorithm"` // default: hmac-sha256
	Timeout       time.Duration `koanf:"timeout"`        // default: 5s
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

// Registration holds agent registration policy settings.
type Registration struct {
	// DomainSuffix is appended to the agentHost submitted by the
	// caller. When set, the agent sends a short name (e.g. "my-agent")
	// and the RA constructs the full FQDN ("my-agent.agents.example.com").
	// When empty, the caller must provide the full FQDN.
	DomainSuffix string `koanf:"domain-suffix"`
}

// RAConfig is the full configuration for ans-ra.
type RAConfig struct {
	Server       Server       `koanf:"server"`
	Auth         Auth         `koanf:"auth"`
	CA           CA           `koanf:"ca"`
	DNS          DNS          `koanf:"dns"`
	Keys         Keys         `koanf:"keys"`
	Store        Store        `koanf:"store"`
	TLClient     TLClient     `koanf:"tl-client"`
	Signer       SignerCfg    `koanf:"signer"`
	Registration Registration `koanf:"registration"`
	Log          Log          `koanf:"log"`
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
	// Server CA is optional but when configured must be valid.
	if c.CA.Server != nil {
		if c.CA.Server.DataDir == "" {
			return errors.New("ca.server.data-dir is required when ca.server block is set")
		}
		if c.CA.Server.ValidityDays <= 0 {
			return errors.New("ca.server.validity-days must be positive")
		}
	}
	switch c.DNS.Type {
	case "noop", "lookup":
	default:
		return fmt.Errorf("dns.type %q not supported (expected 'noop' or 'lookup')", c.DNS.Type)
	}
	applyDNSProvisionerDefaults(c.DNS.Provisioner)
	if err := validateDNSProvisioner(c.DNS.Provisioner); err != nil {
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

// applyDNSProvisionerDefaults fills in default values for optional
// DDNS provisioner fields. Called before validation so that Validate()
// itself is side-effect-free.
func applyDNSProvisionerDefaults(p *DNSProvisionerConfig) {
	if p == nil || p.Type != "ddns" || p.DDNS == nil {
		return
	}
	if p.DDNS.TSIGAlgorithm == "" {
		p.DDNS.TSIGAlgorithm = "hmac-sha256"
	}
	if p.DDNS.Timeout <= 0 {
		p.DDNS.Timeout = 5 * time.Second
	}
}

func validateDNSProvisioner(p *DNSProvisionerConfig) error {
	if p == nil || p.Type == "" {
		return nil
	}
	switch p.Type {
	case "ddns":
		if p.DDNS == nil {
			return errors.New("dns.provisioner.ddns block required when dns.provisioner.type is 'ddns'")
		}
		d := p.DDNS
		if d.Server == "" {
			return errors.New("dns.provisioner.ddns.server is required")
		}
		if d.Zone == "" {
			return errors.New("dns.provisioner.ddns.zone is required")
		}
		if d.TSIGName == "" || d.TSIGSecret == "" {
			return errors.New("dns.provisioner.ddns.tsig-name and tsig-secret are required")
		}
	default:
		return fmt.Errorf("dns.provisioner.type %q not supported (expected 'ddns')", p.Type)
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
