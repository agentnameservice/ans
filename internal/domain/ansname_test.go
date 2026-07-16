package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAnsName(t *testing.T) {
	t.Run("should create valid ans name", func(t *testing.T) {
		n, err := NewAnsName(mustSemVer(1, 0, 0), "agent.example.com")
		require.NoError(t, err)
		assert.Equal(t, "agent.example.com", n.AgentHost())
		assert.Equal(t, mustSemVer(1, 0, 0), n.Version())
	})

	t.Run("should lowercase host", func(t *testing.T) {
		n, err := NewAnsName(mustSemVer(1, 0, 0), "AGENT.EXAMPLE.COM")
		require.NoError(t, err)
		assert.Equal(t, "agent.example.com", n.AgentHost())
	})

	t.Run("should trim whitespace", func(t *testing.T) {
		n, err := NewAnsName(mustSemVer(1, 0, 0), "  agent.example.com  ")
		require.NoError(t, err)
		assert.Equal(t, "agent.example.com", n.AgentHost())
	})

	t.Run("should reject empty host", func(t *testing.T) {
		_, err := NewAnsName(mustSemVer(1, 0, 0), "")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject single label", func(t *testing.T) {
		_, err := NewAnsName(mustSemVer(1, 0, 0), "localhost")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject IP-literal hosts", func(t *testing.T) {
		// An ANS name binds a DNS hostname; accepting an IP would let a
		// registrant aim the HTTP-01 challenge gate at an internal
		// address (e.g. the cloud metadata endpoint). A dotted-quad
		// would otherwise pass the per-label DNS checks as four numeric
		// labels.
		for _, ip := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.1", "8.8.8.8"} {
			_, err := NewAnsName(mustSemVer(1, 0, 0), ip)
			assert.ErrorIsf(t, err, ErrValidation, "IP literal %q must be rejected", ip)
		}
	})

	t.Run("should reject host over 253 chars", func(t *testing.T) {
		// Build a 254-char hostname from repeating valid 63-char labels
		// plus separators plus a 62-char tail: 63+1+63+1+63+1+62 = 254.
		label := strings.Repeat("a", 63)
		host := label + "." + label + "." + label + "." + strings.Repeat("b", 62)
		require.Greater(t, len(host), 253, "test fixture should exceed 253 chars")
		_, err := NewAnsName(mustSemVer(1, 0, 0), host)
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject label over 63 chars", func(t *testing.T) {
		_, err := NewAnsName(mustSemVer(1, 0, 0), strings.Repeat("a", 64)+".com")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject label starting with hyphen", func(t *testing.T) {
		_, err := NewAnsName(mustSemVer(1, 0, 0), "-bad.example.com")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject label ending with hyphen", func(t *testing.T) {
		_, err := NewAnsName(mustSemVer(1, 0, 0), "bad-.example.com")
		assert.ErrorIs(t, err, ErrValidation)
	})
}

func TestParseAnsName(t *testing.T) {
	t.Run("should parse valid ans name", func(t *testing.T) {
		n, err := ParseAnsName("ans://v1.2.3.agent.example.com")
		require.NoError(t, err)
		assert.Equal(t, mustSemVer(1, 2, 3), n.Version())
		assert.Equal(t, "agent.example.com", n.AgentHost())
	})

	t.Run("should parse multi-label host", func(t *testing.T) {
		n, err := ParseAnsName("ans://v1.0.0.a.b.c.example.com")
		require.NoError(t, err)
		assert.Equal(t, "a.b.c.example.com", n.AgentHost())
	})

	t.Run("should reject missing protocol", func(t *testing.T) {
		_, err := ParseAnsName("v1.0.0.agent.example.com")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject missing v prefix", func(t *testing.T) {
		_, err := ParseAnsName("ans://1.0.0.agent.example.com")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject malformed version", func(t *testing.T) {
		_, err := ParseAnsName("ans://v1.0.agent.example.com")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject missing host", func(t *testing.T) {
		_, err := ParseAnsName("ans://v1.0.0.")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject empty input", func(t *testing.T) {
		_, err := ParseAnsName("")
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should round-trip", func(t *testing.T) {
		orig := "ans://v1.2.3.agent.example.com"
		n, err := ParseAnsName(orig)
		require.NoError(t, err)
		assert.Equal(t, orig, n.String())
	})
}

func TestAnsName_String(t *testing.T) {
	n, _ := NewAnsName(mustSemVer(1, 2, 3), "agent.example.com")
	assert.Equal(t, "ans://v1.2.3.agent.example.com", n.String())
}

// TestAnsName_VersionSegment pins the ANS-2 v-prefixed segment form —
// the value TXT builders publish in `version=` and the leading label
// of the ANS name hostname.
func TestAnsName_VersionSegment(t *testing.T) {
	n, _ := NewAnsName(mustSemVer(1, 2, 3), "agent.example.com")
	assert.Equal(t, "v1.2.3", n.VersionSegment())
}

func TestAnsName_FQDN(t *testing.T) {
	n, _ := NewAnsName(mustSemVer(1, 2, 3), "Agent.Example.COM")
	assert.Equal(t, "agent.example.com", n.FQDN())
}

func TestAnsName_IsZero(t *testing.T) {
	assert.True(t, AnsName{}.IsZero())
	n, _ := NewAnsName(mustSemVer(1, 0, 0), "a.b.com")
	assert.False(t, n.IsZero())
}
