package index_test

import (
	"testing"

	"github.com/agentnameservice/ans/internal/finder/index"
)

func TestSupportedField(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		index.FieldType:              true,
		index.FieldTags:              true,
		index.FieldCapabilities:      true,
		index.FieldPublisher:         true,
		index.FieldAttestationType:   true,
		"displayName":                false,
		"":                           false,
		"unknown.path":               false,
		"trustManifest.attestations": false,
	}
	for field, want := range cases {
		if got := index.SupportedField(field); got != want {
			t.Errorf("SupportedField(%q) = %v, want %v", field, got, want)
		}
	}
}

// TestFieldConstants pins the exact dot-path strings the wire contract
// uses, so a rename can't silently diverge from the OpenAPI spec.
func TestFieldConstants(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"type":                            index.FieldType,
		"tags":                            index.FieldTags,
		"capabilities":                    index.FieldCapabilities,
		"publisher":                       index.FieldPublisher,
		"trustManifest.attestations.type": index.FieldAttestationType,
	}
	for literal, constant := range want {
		if literal != constant {
			t.Errorf("field constant drifted: got %q, want %q", constant, literal)
		}
	}
}
