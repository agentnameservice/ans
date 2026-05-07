package domain

import (
	"fmt"
	"strings"
)

// VersionRangeType classifies how a version range matches.
type VersionRangeType int

const (
	// VersionRangeWildcard matches any version.
	VersionRangeWildcard VersionRangeType = iota
	// VersionRangeExact matches a specific version.
	VersionRangeExact
	// VersionRangeCaret is npm-style: ^1.2.3 := >=1.2.3 <2.0.0.
	VersionRangeCaret
	// VersionRangeTilde matches patch updates: ~1.2.3 := >=1.2.3 <1.3.0.
	VersionRangeTilde
)

// VersionRange represents a version matching rule.
type VersionRange struct {
	rangeType VersionRangeType
	version   SimplifiedSemVer // only used for Exact, Caret, Tilde
}

// ParseVersionRange parses a version range string.
// Supported formats: "*", "", "1.2.3", "^1.2.3", "~1.2.3".
func ParseVersionRange(s string) (VersionRange, error) {
	s = strings.TrimSpace(s)

	if s == "" || s == "*" {
		return VersionRange{rangeType: VersionRangeWildcard}, nil
	}

	if strings.HasPrefix(s, "^") {
		v, err := ParseSemVer(s[1:])
		if err != nil {
			return VersionRange{}, NewValidationError(
				"INVALID_VERSION_RANGE",
				fmt.Sprintf("invalid caret version range %q: %v", s, err),
			)
		}
		return VersionRange{rangeType: VersionRangeCaret, version: v}, nil
	}

	if strings.HasPrefix(s, "~") {
		v, err := ParseSemVer(s[1:])
		if err != nil {
			return VersionRange{}, NewValidationError(
				"INVALID_VERSION_RANGE",
				fmt.Sprintf("invalid tilde version range %q: %v", s, err),
			)
		}
		return VersionRange{rangeType: VersionRangeTilde, version: v}, nil
	}

	v, err := ParseSemVer(s)
	if err != nil {
		return VersionRange{}, NewValidationError(
			"INVALID_VERSION_RANGE",
			fmt.Sprintf("invalid version range %q: %v", s, err),
		)
	}
	return VersionRange{rangeType: VersionRangeExact, version: v}, nil
}

// Type returns the range type.
func (r VersionRange) Type() VersionRangeType { return r.rangeType }

// Version returns the base version (zero for Wildcard).
func (r VersionRange) Version() SimplifiedSemVer { return r.version }

// Matches returns true if the given version satisfies this range.
func (r VersionRange) Matches(v SimplifiedSemVer) bool {
	switch r.rangeType {
	case VersionRangeWildcard:
		return true

	case VersionRangeExact:
		return v.Equal(r.version)

	case VersionRangeCaret:
		return r.matchesCaret(v)

	case VersionRangeTilde:
		return r.matchesTilde(v)

	default:
		return false
	}
}

// matchesCaret implements npm-style caret matching:
//   - ^1.2.3 := >=1.2.3, <2.0.0  (major > 0)
//   - ^0.2.3 := >=0.2.3, <0.3.0  (major == 0, minor > 0)
//   - ^0.0.3 := =0.0.3           (major == 0, minor == 0)
func (r VersionRange) matchesCaret(v SimplifiedSemVer) bool {
	if v.Compare(r.version) < 0 {
		return false
	}

	base := r.version
	if base.Major() > 0 {
		return v.Major() == base.Major()
	}
	if base.Minor() > 0 {
		return v.Major() == 0 && v.Minor() == base.Minor()
	}
	// ^0.0.x is exact match.
	return v.Equal(base)
}

// matchesTilde implements tilde matching: ~1.2.3 := >=1.2.3, <1.3.0.
func (r VersionRange) matchesTilde(v SimplifiedSemVer) bool {
	if v.Compare(r.version) < 0 {
		return false
	}
	return v.Major() == r.version.Major() && v.Minor() == r.version.Minor()
}

// String returns the string representation of the range.
func (r VersionRange) String() string {
	switch r.rangeType {
	case VersionRangeWildcard:
		return "*"
	case VersionRangeExact:
		return r.version.String()
	case VersionRangeCaret:
		return "^" + r.version.String()
	case VersionRangeTilde:
		return "~" + r.version.String()
	default:
		return "<unknown>"
	}
}
