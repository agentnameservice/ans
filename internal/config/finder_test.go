package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFile writes YAML content to path or fails the test.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDefaultFinderConfig_Shape(t *testing.T) {
	c := defaultFinderConfig()
	if c.Server.Port != 18082 {
		t.Errorf("default finder port: got %d, want 18082", c.Server.Port)
	}
	if c.Store.Type != "sqlite" {
		t.Errorf("default store type: got %q", c.Store.Type)
	}
	if c.Feed.BaseURL == "" {
		t.Error("default feed base-url must be non-empty")
	}
	if c.Search.MaxPageSize != 100 {
		t.Errorf("default max-page-size: got %d", c.Search.MaxPageSize)
	}
}

func TestLoadFinder_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "finder.yaml")
	yaml := `
server:
  host: "127.0.0.1"
  port: 18082
store:
  type: sqlite
  sqlite:
    path: "` + filepath.Join(dir, "finder.db") + `"
feed:
  base-url: "https://ra.example.org"
  poll-interval: 3s
  page-size: 50
  stale-bound: 30s
tl:
  public-base-url: "https://tl.example.org"
search:
  rate: 10
  burst: 20
  max-page-size: 50
  default-page-size: 5
referrals:
  - identifier: "urn:air:other.example.org:agents:registry"
    display-name: "Other"
    type: "application/ai-registry+json"
    url: "https://other.example.org/v1/"
log:
  level: debug
  format: json
`
	writeFile(t, path, yaml)

	c, err := LoadFinder(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Feed.BaseURL != "https://ra.example.org" {
		t.Errorf("feed base-url: %q", c.Feed.BaseURL)
	}
	if c.Feed.PollInterval != 3*time.Second {
		t.Errorf("poll-interval: %v", c.Feed.PollInterval)
	}
	if c.TL.PublicBaseURL != "https://tl.example.org" {
		t.Errorf("tl public-base-url: %q", c.TL.PublicBaseURL)
	}
	if len(c.Referrals) != 1 || c.Referrals[0].Type != "application/ai-registry+json" {
		t.Errorf("referrals: %+v", c.Referrals)
	}
	if c.Search.DefaultPageSize != 5 {
		t.Errorf("default-page-size: %d", c.Search.DefaultPageSize)
	}
}

func TestLoadFinder_MissingFile(t *testing.T) {
	if _, err := LoadFinder("/nonexistent/finder.yaml"); err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadFinder_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "finder.yaml")
	writeFile(t, path, `
store:
  type: sqlite
  sqlite:
    path: "`+filepath.Join(dir, "f.db")+`"
feed:
  base-url: "https://ra.example.org"
tl:
  public-base-url: "https://tl.example.org"
`)
	// Env keys map ANS_FINDER_A__B → a.b; only non-hyphenated koanf keys
	// (server.port, log.level, …) are reachable this way, matching the
	// RA/TL loaders' behavior. server.port is the canonical override.
	t.Setenv("ANS_FINDER_SERVER__PORT", "19082")
	c, err := LoadFinder(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Server.Port != 19082 {
		t.Errorf("env override not applied: %d", c.Server.Port)
	}
}

func TestFinderConfig_Validate(t *testing.T) {
	t.Parallel()
	base := func() *FinderConfig {
		c := defaultFinderConfig()
		return c
	}
	cases := map[string]struct {
		mutate  func(*FinderConfig)
		wantErr bool
	}{
		"defaults valid":     {func(*FinderConfig) {}, false},
		"port out of range":  {func(c *FinderConfig) { c.Server.Port = 0 }, true},
		"missing store path": {func(c *FinderConfig) { c.Store.SQLite = nil }, true},
		"http feed without override": {func(c *FinderConfig) {
			c.Feed.BaseURL = "http://ra.example.org"
			c.Feed.AllowHTTP = false
		}, true},
		"http feed with override ok": {func(c *FinderConfig) {
			c.Feed.BaseURL = "http://ra.example.org"
			c.Feed.AllowHTTP = true
			c.TL.PublicBaseURL = "http://tl.example.org" // same override applies
		}, false},
		"empty feed url":                       {func(c *FinderConfig) { c.Feed.BaseURL = "" }, true},
		"feed url with query":                  {func(c *FinderConfig) { c.Feed.BaseURL = "https://ra.example.org?x=1" }, true},
		"empty tl url ok (omits attestations)": {func(c *FinderConfig) { c.TL.PublicBaseURL = "" }, false},
		"bad tl url":                           {func(c *FinderConfig) { c.TL.PublicBaseURL = "ftp://tl.example.org" }, true},
		"max-page-size over 100":               {func(c *FinderConfig) { c.Search.MaxPageSize = 500 }, true},
		"default over max": {func(c *FinderConfig) {
			c.Search.MaxPageSize = 10
			c.Search.DefaultPageSize = 50
		}, true},
		"zero poll-interval defaulted": {func(c *FinderConfig) { c.Feed.PollInterval = 0 }, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr != (err != nil) {
				t.Errorf("Validate err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestFinderConfig_DefaultsApplied(t *testing.T) {
	t.Parallel()
	c := &FinderConfig{
		Server: Server{Host: "x", Port: 18082},
		Store:  Store{Type: "sqlite", SQLite: &StoreSQLite{Path: "x.db"}},
		Feed:   FinderFeed{BaseURL: "https://ra.example.org"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Feed.PollInterval != 5*time.Second {
		t.Errorf("poll-interval default: %v", c.Feed.PollInterval)
	}
	if c.Feed.PageSize != 100 {
		t.Errorf("page-size default: %d", c.Feed.PageSize)
	}
	if c.Feed.Timeout != 10*time.Second {
		t.Errorf("timeout default: %v", c.Feed.Timeout)
	}
	if c.Search.MaxPageSize != 100 || c.Search.DefaultPageSize != 10 {
		t.Errorf("search defaults: max=%d default=%d", c.Search.MaxPageSize, c.Search.DefaultPageSize)
	}
}
