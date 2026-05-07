package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSemVer(t *testing.T) {
	t.Run("should create valid semver from components", func(t *testing.T) {
		v, err := NewSemVer(1, 2, 3)
		require.NoError(t, err)
		assert.Equal(t, 1, v.Major())
		assert.Equal(t, 2, v.Minor())
		assert.Equal(t, 3, v.Patch())
	})

	t.Run("should accept zero version", func(t *testing.T) {
		v, err := NewSemVer(0, 0, 0)
		require.NoError(t, err)
		assert.True(t, v.IsZero())
	})

	t.Run("should reject negative major", func(t *testing.T) {
		_, err := NewSemVer(-1, 0, 0)
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject negative minor", func(t *testing.T) {
		_, err := NewSemVer(1, -1, 0)
		assert.ErrorIs(t, err, ErrValidation)
	})

	t.Run("should reject negative patch", func(t *testing.T) {
		_, err := NewSemVer(1, 0, -1)
		assert.ErrorIs(t, err, ErrValidation)
	})
}

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    SimplifiedSemVer
		wantErr bool
	}{
		{"standard version", "1.2.3", SimplifiedSemVer{major: 1, minor: 2, patch: 3}, false},
		{"zero version", "0.0.0", SimplifiedSemVer{}, false},
		{"large version", "100.200.300", SimplifiedSemVer{major: 100, minor: 200, patch: 300}, false},
		{"empty string", "", SimplifiedSemVer{}, true},
		{"missing patch", "1.2", SimplifiedSemVer{}, true},
		{"too many components", "1.2.3.4", SimplifiedSemVer{}, true},
		{"leading zeros", "01.2.3", SimplifiedSemVer{}, true},
		{"alphabetic", "v1.2.3", SimplifiedSemVer{}, true},
		{"negative", "-1.2.3", SimplifiedSemVer{}, true},
		{"whitespace", " 1.2.3 ", SimplifiedSemVer{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSemVer(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSemVer_String(t *testing.T) {
	v, _ := NewSemVer(1, 2, 3)
	assert.Equal(t, "1.2.3", v.String())
}

func TestSemVer_Compare(t *testing.T) {
	tests := []struct {
		a, b SimplifiedSemVer
		want int
	}{
		{mustSemVer(1, 0, 0), mustSemVer(1, 0, 0), 0},
		{mustSemVer(2, 0, 0), mustSemVer(1, 0, 0), 1},
		{mustSemVer(1, 0, 0), mustSemVer(2, 0, 0), -1},
		{mustSemVer(1, 2, 0), mustSemVer(1, 1, 0), 1},
		{mustSemVer(1, 1, 0), mustSemVer(1, 2, 0), -1},
		{mustSemVer(1, 1, 2), mustSemVer(1, 1, 1), 1},
		{mustSemVer(1, 1, 1), mustSemVer(1, 1, 2), -1},
	}
	for _, tc := range tests {
		t.Run(tc.a.String()+" vs "+tc.b.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, tc.a.Compare(tc.b))
		})
	}
}

func TestSemVer_GreaterThan(t *testing.T) {
	v1 := mustSemVer(2, 0, 0)
	v2 := mustSemVer(1, 9, 9)
	assert.True(t, v1.GreaterThan(v2))
	assert.False(t, v2.GreaterThan(v1))
	assert.False(t, v1.GreaterThan(v1))
}

func TestSemVer_Equal(t *testing.T) {
	v1 := mustSemVer(1, 2, 3)
	v2 := mustSemVer(1, 2, 3)
	v3 := mustSemVer(1, 2, 4)
	assert.True(t, v1.Equal(v2))
	assert.False(t, v1.Equal(v3))
}

func TestSemVer_IsZero(t *testing.T) {
	assert.True(t, SimplifiedSemVer{}.IsZero())
	assert.False(t, mustSemVer(0, 0, 1).IsZero())
}

func mustSemVer(major, minor, patch int) SimplifiedSemVer {
	v, err := NewSemVer(major, minor, patch)
	if err != nil {
		panic(err)
	}
	return v
}
