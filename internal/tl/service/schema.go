package service

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/agentnameservice/ans/internal/domain"
)

// SchemaService returns the JSON Schema definition for a given TL
// event schema version. Reference swagger §424 serves this at
// `GET /v1/log/schema/{version}`; we expose it at
// `/v1/log/schema/{version}`.
//
// The schemas themselves are embedded at compile time from the
// `schemas/` directory — no runtime disk lookup, no risk of drift
// between the schema the TL advertises and the envelope shape the
// server actually enforces.
type SchemaService struct {
	schemas map[string][]byte // version → JSON bytes
}

//go:embed schemas/*.json
var schemasFS embed.FS

// NewSchemaService loads every *.json file under the embedded
// schemas/ directory. The filename (without extension) becomes the
// version key — so `schemas/V1.json` serves `/schema/V1`. Returns
// an error at construction time if the embedded FS is empty, which
// indicates a broken build rather than a runtime problem.
func NewSchemaService() (*SchemaService, error) {
	out := make(map[string][]byte)
	err := fs.WalkDir(schemasFS, "schemas", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		body, rerr := schemasFS.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		name := strings.TrimSuffix(strings.TrimPrefix(p, "schemas/"), ".json")
		out[name] = body
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("schema: walk embedded schemas: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("schema: no embedded schemas found; check //go:embed directive")
	}
	return &SchemaService{schemas: out}, nil
}

// Get returns the JSON-schema bytes for the requested version, or
// domain.ErrNotFound (→ 404) when the version isn't known.
//
// We ship three versions, all sharing the reference's flat
// `{logId, producer}` top-level shape with draft-07 + `definitions`:
//
//   - V0, V1 — structural mirrors of the reference TL's schema
//     endpoints so historical verifiers work against us unchanged.
//     The `version` field's pattern is the one ans-wide deviation:
//     `^\d+\.\d+\.\d+$` (bare semver) instead of the reference's
//     `^v\d+\.\d+\.\d+$` — see the "TXT-payload version format"
//     deviation in CLAUDE.md, which states the v-prefixed form only
//     lives inside the ANS name's hostname label.
//   - V2    — V1-shape extended with the attestation deviations this
//     build actually emits: unified `identityCerts[]` /
//     `serverCerts[]` arrays (replacing V1's singleton +
//     rotation-window pair) and typed `dnsRecordsProvisioned[]`
//     records (replacing V1's `map[name]value`).
func (s *SchemaService) Get(_ context.Context, version string) ([]byte, error) {
	body, ok := s.schemas[version]
	if !ok {
		return nil, domain.NewNotFoundError("NOT_FOUND",
			fmt.Sprintf("no schema for version %q", version))
	}
	return body, nil
}
