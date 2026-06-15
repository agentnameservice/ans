package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----- Defaults -----

func TestDefaultRAConfig_Shape(t *testing.T) {
	c := defaultRAConfig()
	if c.Server.Port != 18080 {
		t.Errorf("default RA port: got %d, want 18080", c.Server.Port)
	}
	if c.Auth.Type != "static" {
		t.Errorf("default auth type: got %q", c.Auth.Type)
	}
	if c.CA.Type != "self" {
		t.Errorf("default CA type: got %q", c.CA.Type)
	}
	if c.DNS.Type != "noop" {
		t.Errorf("default DNS type: got %q", c.DNS.Type)
	}
	if c.TLClient.BaseURL == "" {
		t.Error("default tl-client base-url must be non-empty")
	}
}

func TestDefaultTLConfig_Shape(t *testing.T) {
	c := defaultTLConfig()
	if c.Server.Port != 18081 {
		t.Errorf("default TL port: got %d, want 18081", c.Server.Port)
	}
	if c.Merkle.Origin == "" {
		t.Error("default TL merkle origin must be non-empty")
	}
	if c.Merkle.TileStorage.Type != "filesystem" {
		t.Errorf("default tile-storage type: got %q", c.Merkle.TileStorage.Type)
	}
	if !c.Auth.PublicRead {
		t.Error("TL default should allow public reads")
	}
}

// ----- LoadRA -----

func TestLoadRA_MissingFile(t *testing.T) {
	_, err := LoadRA("/nonexistent/does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadRA_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ra.yaml")
	yaml := `
server:
  host: "127.0.0.1"
  port: 9090
auth:
  type: static
  static:
    api-key: "dev-key"
ca:
  type: self
  self:
    org: "Test CA"
    validity-days: 30
    data-dir: "` + dir + `/ca"
dns:
  type: noop
keys:
  type: file
  file:
    path: "` + dir + `/keys"
store:
  type: sqlite
  sqlite:
    path: "` + dir + `/db"
tl-client:
  base-url: "http://localhost:18081"
log:
  level: info
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadRA(path)
	if err != nil {
		t.Fatalf("LoadRA: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("port: got %d want 9090", cfg.Server.Port)
	}
	if cfg.Auth.Static.APIKey != "dev-key" {
		t.Errorf("api key not loaded: got %q", cfg.Auth.Static.APIKey)
	}
	// Default applied: TLClient.Timeout is non-zero.
	if cfg.TLClient.Timeout <= 0 {
		t.Error("tl-client timeout default not applied")
	}
}

func TestLoadRA_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ra.yaml")
	// File says port 9090; env override pushes to 19000.
	os.WriteFile(path, []byte(`
server: {host: "127.0.0.1", port: 9090}
auth: {type: static, static: {api-key: "x"}}
ca: {type: self, self: {org: "t", validity-days: 1, data-dir: "`+dir+`"}}
dns: {type: noop}
keys: {type: file, file: {path: "`+dir+`"}}
store: {type: sqlite, sqlite: {path: "`+dir+`/db"}}
tl-client: {base-url: "http://x"}
`), 0o600)

	t.Setenv("ANS_RA_SERVER__PORT", "19000")
	cfg, err := LoadRA(path)
	if err != nil {
		t.Fatalf("LoadRA: %v", err)
	}
	if cfg.Server.Port != 19000 {
		t.Errorf("env override ignored: got port %d, want 19000", cfg.Server.Port)
	}
}

func TestLoadRA_ValidationFailure(t *testing.T) {
	// Missing tl-client.base-url → Validate fails after unmarshal.
	dir := t.TempDir()
	path := filepath.Join(dir, "ra.yaml")
	os.WriteFile(path, []byte(`
server: {port: 9090}
auth: {type: static, static: {api-key: "x"}}
ca: {type: self, self: {org: "o", validity-days: 1, data-dir: "`+dir+`"}}
dns: {type: noop}
keys: {type: file, file: {path: "`+dir+`"}}
store: {type: sqlite, sqlite: {path: "`+dir+`/db"}}
tl-client: {base-url: ""}
`), 0o600)

	_, err := LoadRA(path)
	if err == nil {
		t.Fatal("expected Validate failure")
	}
	if !strings.Contains(err.Error(), "tl-client.base-url") {
		t.Errorf("expected tl-client.base-url error, got %v", err)
	}
}

// ----- LoadTL -----

func TestLoadTL_MissingFile(t *testing.T) {
	_, err := LoadTL("/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadTL_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tl.yaml")
	os.WriteFile(path, []byte(`
server: {host: "127.0.0.1", port: 18081}
auth: {type: static, static: {api-key: "tl-key"}, public-read: true}
keys: {type: file, file: {path: "`+dir+`/keys"}}
store: {type: sqlite, sqlite: {path: "`+dir+`/db"}}
merkle:
  origin: "ans-demo"
  tile-storage:
    type: filesystem
    filesystem:
      path: "`+dir+`/tiles"
  checkpoint-interval: 3s
log:
  level: debug
`), 0o600)
	cfg, err := LoadTL(path)
	if err != nil {
		t.Fatalf("LoadTL: %v", err)
	}
	if cfg.Merkle.Origin != "ans-demo" {
		t.Errorf("origin: got %q want ans-demo", cfg.Merkle.Origin)
	}
	if cfg.Merkle.CheckpointInterval != 3*time.Second {
		t.Errorf("checkpoint interval: got %v want 3s", cfg.Merkle.CheckpointInterval)
	}
}

// ----- RAConfig.Validate error branches -----

func TestRAConfig_Validate_Errors(t *testing.T) {
	dir := t.TempDir()
	good := func() *RAConfig {
		// Start from defaults, fill in a valid path.
		c := defaultRAConfig()
		c.Auth.Static = &AuthStatic{APIKey: "x"}
		c.CA.Self.DataDir = dir
		c.Keys.File.Path = dir
		c.Store.SQLite.Path = filepath.Join(dir, "db")
		return c
	}
	tests := []struct {
		name   string
		mutate func(c *RAConfig)
		want   string
	}{
		{"port out of range: 0", func(c *RAConfig) { c.Server.Port = 0 }, "server.port"},
		{"port out of range: huge", func(c *RAConfig) { c.Server.Port = 70000 }, "server.port"},
		{"unsupported ca.type", func(c *RAConfig) { c.CA.Type = "vault" }, "ca.type"},
		{"missing ca.self.data-dir", func(c *RAConfig) { c.CA.Self.DataDir = "" }, "ca.self.data-dir"},
		{"invalid ca.self.validity-days", func(c *RAConfig) { c.CA.Self.ValidityDays = 0 }, "validity-days"},
		{"server CA missing data-dir", func(c *RAConfig) {
			c.CA.Server = &CAServerSelf{ValidityDays: 7}
		}, "ca.server.data-dir"},
		{"server CA bad validity", func(c *RAConfig) {
			c.CA.Server = &CAServerSelf{DataDir: dir, ValidityDays: 0}
		}, "ca.server.validity-days"},
		{"unsupported dns.type", func(c *RAConfig) { c.DNS.Type = "bind" }, "dns.type"},
		{"unsupported keys.type", func(c *RAConfig) { c.Keys.Type = "vault" }, "keys.type"},
		{"missing keys.file.path", func(c *RAConfig) { c.Keys.File.Path = "" }, "keys.file.path"},
		{"unsupported store.type", func(c *RAConfig) { c.Store.Type = "postgres" }, "store.type"},
		{"missing store.sqlite.path", func(c *RAConfig) { c.Store.SQLite.Path = "" }, "store.sqlite.path"},
		{"missing tl-client.base-url", func(c *RAConfig) { c.TLClient.BaseURL = "" }, "tl-client.base-url"},
		{"unsupported dns.provisioner.type", func(c *RAConfig) {
			c.DNS.Provisioner = &DNSProvisionerConfig{Type: "bogus"}
		}, "dns.provisioner.type"},
		{"ddns missing block", func(c *RAConfig) {
			c.DNS.Provisioner = &DNSProvisionerConfig{Type: "ddns"}
		}, "dns.provisioner.ddns block"},
		{"ddns missing server", func(c *RAConfig) {
			c.DNS.Provisioner = &DNSProvisionerConfig{Type: "ddns", DDNS: &DNSDDNSConfig{Zone: "z.", TSIGName: "k.", TSIGSecret: "s"}}
		}, "ddns.server"},
		{"ddns missing zone", func(c *RAConfig) {
			c.DNS.Provisioner = &DNSProvisionerConfig{Type: "ddns", DDNS: &DNSDDNSConfig{Server: "s:53", TSIGName: "k.", TSIGSecret: "s"}}
		}, "ddns.zone"},
		{"ddns missing tsig", func(c *RAConfig) {
			c.DNS.Provisioner = &DNSProvisionerConfig{Type: "ddns", DDNS: &DNSDDNSConfig{Server: "s:53", Zone: "z."}}
		}, "tsig-name"},
		{"public-base-url http scheme", func(c *RAConfig) {
			c.TLClient.PublicBaseURL = "http://tl.example.com"
		}, "https scheme"},
		{"public-base-url with userinfo", func(c *RAConfig) {
			c.TLClient.PublicBaseURL = "https://user:pass@tl.example.com"
		}, "userinfo not allowed"},
		{"public-base-url with query", func(c *RAConfig) {
			c.TLClient.PublicBaseURL = "https://tl.example.com?foo=bar"
		}, "query string not allowed"},
		{"public-base-url with fragment", func(c *RAConfig) {
			c.TLClient.PublicBaseURL = "https://tl.example.com#frag"
		}, "fragment not allowed"},
		{"public-base-url empty", func(c *RAConfig) {
			c.TLClient.PublicBaseURL = ""
		}, "public-base-url is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestRAConfig_Validate_DDNSDefaults(t *testing.T) {
	dir := t.TempDir()
	c := defaultRAConfig()
	c.Auth.Static = &AuthStatic{APIKey: "x"}
	c.CA.Self.DataDir = dir
	c.Keys.File.Path = dir
	c.Store.SQLite.Path = filepath.Join(dir, "db")
	c.DNS.Provisioner = &DNSProvisionerConfig{
		Type: "ddns",
		DDNS: &DNSDDNSConfig{
			Server:     "127.0.0.1:53",
			Zone:       "example.com.",
			TSIGName:   "ans-key.",
			TSIGSecret: "c2VjcmV0",
		},
	}

	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.DNS.Provisioner.DDNS.TSIGAlgorithm != "hmac-sha256" {
		t.Errorf("TSIGAlgorithm default not applied: got %q", c.DNS.Provisioner.DDNS.TSIGAlgorithm)
	}
	if c.DNS.Provisioner.DDNS.Timeout != 5*time.Second {
		t.Errorf("Timeout default not applied: got %v", c.DNS.Provisioner.DDNS.Timeout)
	}
}

func TestRAConfig_Validate_AppliesDefaultTLClientTimeout(t *testing.T) {
	dir := t.TempDir()
	c := defaultRAConfig()
	c.Auth.Static = &AuthStatic{APIKey: "x"}
	c.CA.Self.DataDir = dir
	c.Keys.File.Path = dir
	c.Store.SQLite.Path = filepath.Join(dir, "db")
	c.TLClient.Timeout = 0 // intentionally unset

	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.TLClient.Timeout != 10*time.Second {
		t.Errorf("timeout default not applied: got %v", c.TLClient.Timeout)
	}
}

// ----- TLConfig.Validate error branches -----

func TestTLConfig_Validate_Errors(t *testing.T) {
	dir := t.TempDir()
	good := func() *TLConfig {
		c := defaultTLConfig()
		c.Auth.Static = &AuthStatic{APIKey: "x"}
		c.Keys.File.Path = dir
		c.Store.SQLite.Path = filepath.Join(dir, "db")
		c.Merkle.TileStorage.Filesystem.Path = filepath.Join(dir, "tiles")
		return c
	}
	tests := []struct {
		name   string
		mutate func(c *TLConfig)
		want   string
	}{
		{"bad port", func(c *TLConfig) { c.Server.Port = -1 }, "server.port"},
		{"missing merkle.origin", func(c *TLConfig) { c.Merkle.Origin = "" }, "merkle.origin"},
		{"bad tile-storage.type", func(c *TLConfig) { c.Merkle.TileStorage.Type = "s3" }, "tile-storage.type"},
		{"missing tile-storage path", func(c *TLConfig) {
			c.Merkle.TileStorage.Filesystem = nil
		}, "tile-storage.filesystem.path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestTLConfig_Validate_AppliesDefaultCheckpointInterval(t *testing.T) {
	dir := t.TempDir()
	c := defaultTLConfig()
	c.Auth.Static = &AuthStatic{APIKey: "x"}
	c.Keys.File.Path = dir
	c.Store.SQLite.Path = filepath.Join(dir, "db")
	c.Merkle.TileStorage.Filesystem.Path = filepath.Join(dir, "tiles")
	c.Merkle.CheckpointInterval = 0

	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Merkle.CheckpointInterval != 10*time.Second {
		t.Errorf("checkpoint-interval default not applied: got %v", c.Merkle.CheckpointInterval)
	}
}

// ----- validateAuth -----

func TestValidateAuth(t *testing.T) {
	t.Run("static ok", func(t *testing.T) {
		if err := validateAuth(&Auth{Type: "static", Static: &AuthStatic{APIKey: "x"}}); err != nil {
			t.Errorf("got %v", err)
		}
	})
	t.Run("static missing key", func(t *testing.T) {
		err := validateAuth(&Auth{Type: "static", Static: &AuthStatic{}})
		if err == nil || !strings.Contains(err.Error(), "api-key") {
			t.Errorf("expected api-key error, got %v", err)
		}
	})
	t.Run("static nil sub-config", func(t *testing.T) {
		err := validateAuth(&Auth{Type: "static"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("oidc ok", func(t *testing.T) {
		if err := validateAuth(&Auth{Type: "oidc", OIDC: &AuthOIDC{IssuerURL: "http://x", Audience: "a"}}); err != nil {
			t.Errorf("got %v", err)
		}
	})
	t.Run("oidc missing audience", func(t *testing.T) {
		err := validateAuth(&Auth{Type: "oidc", OIDC: &AuthOIDC{IssuerURL: "http://x"}})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("oidc nil sub-config", func(t *testing.T) {
		err := validateAuth(&Auth{Type: "oidc"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("unknown type", func(t *testing.T) {
		err := validateAuth(&Auth{Type: "kerberos"})
		if err == nil || !strings.Contains(err.Error(), "auth.type") {
			t.Errorf("expected auth.type error, got %v", err)
		}
	})
}

// ----- validateKeys -----

func TestValidateKeys(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if err := validateKeys(&Keys{Type: "file", File: &KeysFile{Path: "/tmp"}}); err != nil {
			t.Errorf("got %v", err)
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		err := validateKeys(&Keys{Type: "kms"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil file", func(t *testing.T) {
		err := validateKeys(&Keys{Type: "file"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("empty path", func(t *testing.T) {
		err := validateKeys(&Keys{Type: "file", File: &KeysFile{}})
		if err == nil {
			t.Error("expected error")
		}
	})
}

// ----- validateStore -----

func TestValidateStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if err := validateStore(&Store{Type: "sqlite", SQLite: &StoreSQLite{Path: "/tmp/db"}}); err != nil {
			t.Errorf("got %v", err)
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		err := validateStore(&Store{Type: "mysql"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("nil sqlite", func(t *testing.T) {
		err := validateStore(&Store{Type: "sqlite"})
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("empty path", func(t *testing.T) {
		err := validateStore(&Store{Type: "sqlite", SQLite: &StoreSQLite{}})
		if err == nil {
			t.Error("expected error")
		}
	})
}
