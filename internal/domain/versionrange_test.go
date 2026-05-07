package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersionRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    VersionRangeType
		wantErr bool
	}{
		{"wildcard star", "*", VersionRangeWildcard, false},
		{"wildcard empty", "", VersionRangeWildcard, false},
		{"wildcard whitespace", "   ", VersionRangeWildcard, false},
		{"exact", "1.2.3", VersionRangeExact, false},
		{"caret", "^1.2.3", VersionRangeCaret, false},
		{"tilde", "~1.2.3", VersionRangeTilde, false},
		{"invalid exact", "1.2", 0, true},
		{"invalid caret", "^abc", 0, true},
		{"invalid tilde", "~xyz", 0, true},
		{"garbage", "not-a-version", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseVersionRange(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, r.Type())
		})
	}
}

func TestVersionRange_Wildcard_Matches(t *testing.T) {
	r, _ := ParseVersionRange("*")
	assert.True(t, r.Matches(mustSemVer(0, 0, 0)))
	assert.True(t, r.Matches(mustSemVer(99, 99, 99)))
}

func TestVersionRange_Exact_Matches(t *testing.T) {
	r, _ := ParseVersionRange("1.2.3")
	assert.True(t, r.Matches(mustSemVer(1, 2, 3)))
	assert.False(t, r.Matches(mustSemVer(1, 2, 4)))
	assert.False(t, r.Matches(mustSemVer(2, 0, 0)))
}

func TestVersionRange_Caret_Matches(t *testing.T) {
	t.Run("major greater than 0", func(t *testing.T) {
		r, _ := ParseVersionRange("^1.2.3")
		// Base and above within same major.
		assert.True(t, r.Matches(mustSemVer(1, 2, 3)))
		assert.True(t, r.Matches(mustSemVer(1, 2, 9)))
		assert.True(t, r.Matches(mustSemVer(1, 9, 0)))
		// Below base — no match.
		assert.False(t, r.Matches(mustSemVer(1, 2, 2)))
		assert.False(t, r.Matches(mustSemVer(1, 1, 99)))
		// Different major — no match.
		assert.False(t, r.Matches(mustSemVer(2, 0, 0)))
	})

	t.Run("major 0 minor greater than 0", func(t *testing.T) {
		r, _ := ParseVersionRange("^0.2.3")
		assert.True(t, r.Matches(mustSemVer(0, 2, 3)))
		assert.True(t, r.Matches(mustSemVer(0, 2, 9)))
		assert.False(t, r.Matches(mustSemVer(0, 3, 0)))
		assert.False(t, r.Matches(mustSemVer(0, 2, 2)))
		assert.False(t, r.Matches(mustSemVer(1, 0, 0)))
	})

	t.Run("major 0 minor 0 is exact", func(t *testing.T) {
		r, _ := ParseVersionRange("^0.0.3")
		assert.True(t, r.Matches(mustSemVer(0, 0, 3)))
		assert.False(t, r.Matches(mustSemVer(0, 0, 4)))
		assert.False(t, r.Matches(mustSemVer(0, 0, 2)))
	})
}

func TestVersionRange_Tilde_Matches(t *testing.T) {
	r, _ := ParseVersionRange("~1.2.3")
	assert.True(t, r.Matches(mustSemVer(1, 2, 3)))
	assert.True(t, r.Matches(mustSemVer(1, 2, 9)))
	assert.False(t, r.Matches(mustSemVer(1, 3, 0)))
	assert.False(t, r.Matches(mustSemVer(1, 2, 2)))
	assert.False(t, r.Matches(mustSemVer(2, 2, 3)))
}

func TestVersionRange_String(t *testing.T) {
	cases := map[string]string{
		"*":      "*",
		"1.2.3":  "1.2.3",
		"^1.2.3": "^1.2.3",
		"~1.2.3": "~1.2.3",
	}
	for in, want := range cases {
		r, err := ParseVersionRange(in)
		require.NoError(t, err)
		assert.Equal(t, want, r.String())
	}
}

func TestVersionRange_Type_Accessors(t *testing.T) {
	r, _ := ParseVersionRange("^1.2.3")
	assert.Equal(t, VersionRangeCaret, r.Type())
	assert.Equal(t, mustSemVer(1, 2, 3), r.Version())
}

// Unknown type defensive path — constructed manually since parser won't produce it.
func TestVersionRange_UnknownType_DoesNotMatch(t *testing.T) {
	r := VersionRange{rangeType: VersionRangeType(99)}
	assert.False(t, r.Matches(mustSemVer(1, 0, 0)))
	assert.Equal(t, "<unknown>", r.String())
}
