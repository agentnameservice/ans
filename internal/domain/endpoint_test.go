package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentFunction_Validate(t *testing.T) {
	t.Run("valid function", func(t *testing.T) {
		f := AgentFunction{ID: "f1", Name: "Translate", Tags: []string{"nlp", "en"}}
		assert.NoError(t, f.Validate())
	})

	t.Run("reject blank id", func(t *testing.T) {
		err := AgentFunction{ID: "  ", Name: "ok"}.Validate()
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("reject blank name", func(t *testing.T) {
		err := AgentFunction{ID: "id", Name: ""}.Validate()
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("reject long tag", func(t *testing.T) {
		err := AgentFunction{ID: "id", Name: "n", Tags: []string{strings.Repeat("x", 21)}}.Validate()
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("reject too many tags", func(t *testing.T) {
		tags := make([]string, 21)
		for i := range tags {
			tags[i] = "t"
		}
		err := AgentFunction{ID: "id", Name: "n", Tags: tags}.Validate()
		assert.ErrorIs(t, err, ErrValidation)
	})
}

func TestAgentEndpoint_Validate(t *testing.T) {
	valid := AgentEndpoint{
		Protocol:   ProtocolMCP,
		AgentURL:   "https://agent.example.com/mcp",
		Transports: []Transport{TransportSSE},
	}

	t.Run("valid minimal", func(t *testing.T) {
		assert.NoError(t, valid.Validate())
	})

	t.Run("reject invalid protocol", func(t *testing.T) {
		e := valid
		e.Protocol = Protocol("BAD")
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject bad agent url", func(t *testing.T) {
		e := valid
		e.AgentURL = ""
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject bad metadata url", func(t *testing.T) {
		e := valid
		e.MetadataURL = "not a url"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	// Out-of-range ports parse fine through url.Parse but produce SVCB
	// port= SvcParams and _<port>._tcp. TLSA owner names no DNS
	// provider accepts — the boundary must reject them loudly instead
	// of stranding the operator at verify-dns.
	t.Run("reject port above 65535", func(t *testing.T) {
		e := valid
		e.AgentURL = "https://agent.example.com:99999/mcp"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject port zero", func(t *testing.T) {
		e := valid
		e.AgentURL = "https://agent.example.com:0/mcp"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject overflowing port literal", func(t *testing.T) {
		e := valid
		e.AgentURL = "https://agent.example.com:443443443443/mcp"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("accept explicit in-range port", func(t *testing.T) {
		e := valid
		e.AgentURL = "https://agent.example.com:8443/mcp"
		assert.NoError(t, e.Validate())
	})

	t.Run("reject bad documentation url", func(t *testing.T) {
		e := valid
		e.DocumentationURL = "not a url"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject metadata hash without metadata url", func(t *testing.T) {
		e := valid
		e.MetadataHash = "SHA256:" + strings.Repeat("a", 64)
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject malformed metadata hash", func(t *testing.T) {
		e := valid
		e.MetadataURL = "https://agent.example.com/meta"
		e.MetadataHash = "SHA256:short"
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("accept well-formed metadata hash", func(t *testing.T) {
		e := valid
		e.MetadataURL = "https://agent.example.com/meta"
		e.MetadataHash = "SHA256:" + strings.Repeat("a", 64)
		assert.NoError(t, e.Validate())
	})

	t.Run("reject duplicate function ids", func(t *testing.T) {
		e := valid
		e.Functions = []AgentFunction{
			{ID: "f1", Name: "A"},
			{ID: "f1", Name: "B"},
		}
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject bad function", func(t *testing.T) {
		e := valid
		e.Functions = []AgentFunction{{ID: "", Name: "x"}}
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})

	t.Run("reject invalid transport", func(t *testing.T) {
		e := valid
		e.Transports = []Transport{Transport("FOO")}
		assert.ErrorIs(t, e.Validate(), ErrValidation)
	})
}

func TestAgentEndpoint_ValidateHostMatch(t *testing.T) {
	e := AgentEndpoint{Protocol: ProtocolMCP, AgentURL: "https://Agent.Example.com/mcp"}

	t.Run("matches case-insensitive", func(t *testing.T) {
		assert.NoError(t, e.ValidateHostMatch("agent.example.com"))
	})

	t.Run("mismatched host", func(t *testing.T) {
		assert.ErrorIs(t, e.ValidateHostMatch("other.example.com"), ErrValidation)
	})

	t.Run("invalid url", func(t *testing.T) {
		bad := AgentEndpoint{AgentURL: "://:::nope"}
		assert.ErrorIs(t, bad.ValidateHostMatch("x"), ErrValidation)
	})
}

func TestAgentEndpoints_Validate(t *testing.T) {
	fqdn := "agent.example.com"

	good := AgentEndpoints{
		AgentID: "id",
		Endpoints: []AgentEndpoint{
			{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			{Protocol: ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
		},
	}

	t.Run("valid collection", func(t *testing.T) {
		require.NoError(t, good.Validate(fqdn))
	})

	t.Run("empty collection", func(t *testing.T) {
		e := AgentEndpoints{AgentID: "id"}
		assert.ErrorIs(t, e.Validate(fqdn), ErrValidation)
	})

	t.Run("duplicate protocol", func(t *testing.T) {
		e := AgentEndpoints{
			AgentID: "id",
			Endpoints: []AgentEndpoint{
				{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/a"},
				{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/b"},
			},
		}
		assert.ErrorIs(t, e.Validate(fqdn), ErrValidation)
	})

	t.Run("duplicate protocol+url", func(t *testing.T) {
		e := AgentEndpoints{
			AgentID: "id",
			Endpoints: []AgentEndpoint{
				{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/x"},
				{Protocol: ProtocolMCP, AgentURL: "https://agent.example.com/x"},
			},
		}
		assert.ErrorIs(t, e.Validate(fqdn), ErrValidation)
	})

	t.Run("host mismatch", func(t *testing.T) {
		e := AgentEndpoints{
			AgentID: "id",
			Endpoints: []AgentEndpoint{
				{Protocol: ProtocolMCP, AgentURL: "https://other.example.com/mcp"},
			},
		}
		assert.ErrorIs(t, e.Validate(fqdn), ErrValidation)
	})

	t.Run("bad endpoint rejected per-entry", func(t *testing.T) {
		// Covers the `ep.Validate()` failure branch in AgentEndpoints.Validate
		// (endpoint.go:168-170). A per-endpoint failure — here an unknown
		// protocol — is surfaced before the collection-level dedup checks.
		e := AgentEndpoints{
			AgentID: "id",
			Endpoints: []AgentEndpoint{
				{Protocol: Protocol("WAT"), AgentURL: "https://agent.example.com/mcp"},
			},
		}
		err := e.Validate(fqdn)
		assert.ErrorIs(t, err, ErrValidation)
	})
}
