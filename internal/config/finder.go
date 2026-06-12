package config

import (
	"errors"
	"fmt"
	"time"
)

// FinderConfig is the full configuration for ans-finder.
//
// The Finder polls the RA's agent-events feed (Feed), projects events
// into a SQLite FTS5 index (Store), and serves the ARD search/explore
// surface (Server, Search). TL carries the Transparency Log's public base
// URL used to build each entry's SCITT receipt attestation URI. Referrals
// are the config-only federation entries returned in `referrals` mode.
type FinderConfig struct {
	Server    Server           `koanf:"server"`
	Store     Store            `koanf:"store"`
	Feed      FinderFeed       `koanf:"feed"`
	TL        FinderTL         `koanf:"tl"`
	Search    FinderSearch     `koanf:"search"`
	Referrals []FinderReferral `koanf:"referrals"`
	Log       Log              `koanf:"log"`
}

// FinderFeed configures the agent-events feed poller.
type FinderFeed struct {
	// BaseURL is the RA's externally-reachable base, e.g.
	// "https://ra.ans.example.org". The poller GETs {BaseURL}/v1/agents/
	// events. Must be https unless AllowHTTP is set.
	BaseURL string `koanf:"base-url"`
	// AllowHTTP relaxes the feed transport policy to permit plaintext
	// http — a dev override only. TLS verification is never skipped.
	AllowHTTP bool `koanf:"allow-http"`
	// PollInterval is the delay between poll rounds.
	PollInterval time.Duration `koanf:"poll-interval"`
	// PageSize is the per-request limit passed to the feed.
	PageSize int `koanf:"page-size"`
	// Timeout bounds each feed HTTP request.
	Timeout time.Duration `koanf:"timeout"`
	// StaleBound is how far behind the last successful poll the index may
	// fall before responses carry staleSince. Zero disables the signal.
	StaleBound time.Duration `koanf:"stale-bound"`
}

// FinderTL configures the Transparency Log linkage.
type FinderTL struct {
	// PublicBaseURL is the TL's externally-reachable base, woven into each
	// entry's ANS-Registration attestation URI
	// ({PublicBaseURL}/v1/agents/{id}/receipt). Empty omits attestations.
	// Must be https unless the feed's AllowHTTP override is set (the
	// receipt URI a client follows should be verifiable).
	PublicBaseURL string `koanf:"public-base-url"`
}

// FinderSearch configures the search surface.
type FinderSearch struct {
	// Rate is the token-bucket refill rate (requests/second) on the
	// unauthenticated search/explore routes. Zero (with any burst)
	// disables rate limiting.
	Rate float64 `koanf:"rate"`
	// Burst is the token-bucket ceiling.
	Burst float64 `koanf:"burst"`
	// MaxPageSize caps the per-page result count (spec max 100).
	MaxPageSize int `koanf:"max-page-size"`
	// DefaultPageSize is used when a request omits pageSize (spec 10).
	DefaultPageSize int `koanf:"default-page-size"`
	// SourceURL is the Finder's own base URL echoed as a result's
	// `source`. Defaults to "http://{server.host}:{server.port}/v1/" when
	// empty.
	SourceURL string `koanf:"source-url"`
}

// FinderReferral is one config-supplied federation referral: a catalog
// entry describing another registry the client MAY query. The Finder
// never auto-follows referrals.
type FinderReferral struct {
	Identifier  string `koanf:"identifier"`
	DisplayName string `koanf:"display-name"`
	Type        string `koanf:"type"`
	URL         string `koanf:"url"`
}

// LoadFinder loads and validates ans-finder configuration from the given
// YAML path. Environment variables prefixed with ANS_FINDER_ override
// file values; a double underscore maps to a nesting dot, e.g.
// ANS_FINDER_SERVER__PORT sets server.port.
//
// Only config keys WITHOUT a hyphen are reachable via the environment:
// the env mapper lowercases the variable and turns "__" into ".", so it
// cannot produce a hyphenated koanf key. Hyphenated keys (feed.base-url,
// search.max-page-size, …) are therefore file-only. This matches the RA
// and TL loaders, which share the same mapper; do not special-case the
// finder's mapper to add hyphen support (it would diverge the three
// binaries and risk collisions).
func LoadFinder(path string) (*FinderConfig, error) {
	k, err := loadKoanf(path, "ANS_FINDER_")
	if err != nil {
		return nil, err
	}
	cfg := defaultFinderConfig()
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// Validate ensures the finder config is internally consistent and applies
// in-range defaults for unset tunables.
func (c *FinderConfig) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port out of range: %d", c.Server.Port)
	}
	if err := validateStore(&c.Store); err != nil {
		return err
	}
	if err := validateFeedURL(c.Feed.BaseURL, c.Feed.AllowHTTP); err != nil {
		return err
	}
	if c.Feed.PollInterval <= 0 {
		c.Feed.PollInterval = 5 * time.Second
	}
	if c.Feed.PageSize <= 0 {
		c.Feed.PageSize = 100
	}
	if c.Feed.Timeout <= 0 {
		c.Feed.Timeout = 10 * time.Second
	}
	// StaleBound may legitimately be zero (signal disabled), so it is not
	// defaulted here.

	// The TL public base URL is optional (empty omits attestations); when
	// present it must satisfy the same scheme policy as the feed so the
	// receipt URI a client follows is verifiable. Validate it under its own
	// label so the error names the right field.
	if c.TL.PublicBaseURL != "" {
		if err := validateAbsoluteServiceURL(c.TL.PublicBaseURL, c.Feed.AllowHTTP, "tl.public-base-url"); err != nil {
			return err
		}
	}

	if c.Search.MaxPageSize <= 0 {
		c.Search.MaxPageSize = 100
	}
	if c.Search.MaxPageSize > 100 {
		// The ARD spec caps pageSize at 100; refuse a config that would
		// advertise a larger page than the contract permits.
		return fmt.Errorf("search.max-page-size %d exceeds the spec maximum of 100", c.Search.MaxPageSize)
	}
	if c.Search.DefaultPageSize <= 0 {
		c.Search.DefaultPageSize = 10
	}
	if c.Search.DefaultPageSize > c.Search.MaxPageSize {
		return fmt.Errorf("search.default-page-size %d exceeds max-page-size %d",
			c.Search.DefaultPageSize, c.Search.MaxPageSize)
	}
	return nil
}

// validateFeedURL applies the feed/TL transport policy: absolute, https
// (http only under allowHTTP), no userinfo/query/fragment. Reuses the
// same checks as the RA's public-base-url validator so the rule is
// consistent across the codebase.
func validateFeedURL(raw string, allowHTTP bool) error {
	if raw == "" {
		return errors.New("feed.base-url is required")
	}
	return validateAbsoluteServiceURL(raw, allowHTTP, "feed.base-url")
}
