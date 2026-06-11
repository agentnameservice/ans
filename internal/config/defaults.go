package config

import "time"

// defaultRAConfig returns an RAConfig pre-populated with sensible defaults.
// Values from the YAML file and environment variables override these.
func defaultRAConfig() *RAConfig {
	return &RAConfig{
		Server: Server{Host: "0.0.0.0", Port: 18080},
		Auth: Auth{
			Type:   "static",
			Static: &AuthStatic{APIKey: ""},
		},
		CA: CA{
			Type: "self",
			Self: &CASelf{
				Org:          "ANS Local Dev CA",
				ValidityDays: 365,
				DataDir:      "./data/ra/ca",
			},
		},
		DNS: DNS{Type: "noop"},
		Identity: Identity{
			Resolver:          IdentityResolver{Type: "noop"},
			ChallengeTTL:      time.Hour,
			RegisterRateLimit: 10,
			LinkRateLimit:     60,
			SealTimeout:       5 * time.Second,
		},
		Keys: Keys{
			Type: "file",
			File: &KeysFile{Path: "./data/ra/keys"},
		},
		Store: Store{
			Type:   "sqlite",
			SQLite: &StoreSQLite{Path: "./data/ra/ans.db"},
		},
		TLClient: TLClient{
			BaseURL:       "http://localhost:18081",
			PublicBaseURL: "https://localhost:18081",
			APIKey:        "",
			Timeout:       10 * time.Second,
			BatchSize:     10,
			PollInterval:  2 * time.Second,
			MaxBackoff:    5 * time.Minute,
			Disabled:      false,
		},
		Signer: SignerCfg{
			KeyID: "ans-ra-signer",
			RaID:  "ans-ra-local",
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// defaultTLConfig returns a TLConfig pre-populated with sensible defaults.
func defaultTLConfig() *TLConfig {
	return &TLConfig{
		Server: Server{Host: "0.0.0.0", Port: 18081},
		Auth: Auth{
			Type:       "static",
			Static:     &AuthStatic{APIKey: ""},
			PublicRead: true,
		},
		Keys: Keys{
			Type: "file",
			File: &KeysFile{Path: "./data/tl/keys"},
		},
		Store: Store{
			Type:   "sqlite",
			SQLite: &StoreSQLite{Path: "./data/tl/tl.db"},
		},
		Merkle: Merkle{
			Origin: "ans-local-dev",
			TileStorage: TileStorage{
				Type: "filesystem",
				Filesystem: &TileStorageFilesystem{
					Path: "./data/tl/tiles",
				},
			},
			CheckpointInterval: 10 * time.Second,
		},
		Attestation: AttestationKeyCfg{
			KeyID: "ans-tl-attestation",
		},
		Log: Log{Level: "info", Format: "text"},
	}
}
