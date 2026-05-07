package domain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// SimplifiedSemVer represents a simplified semantic version (major.minor.patch).
// All components must be non-negative integers.
type SimplifiedSemVer struct {
	major int
	minor int
	patch int
}

// NewSemVer creates a SimplifiedSemVer from individual components.
func NewSemVer(major, minor, patch int) (SimplifiedSemVer, error) {
	if major < 0 || minor < 0 || patch < 0 {
		return SimplifiedSemVer{}, NewValidationError(
			"INVALID_SEMVER",
			fmt.Sprintf("version components must be non-negative: %d.%d.%d", major, minor, patch),
		)
	}
	return SimplifiedSemVer{major: major, minor: minor, patch: patch}, nil
}

// ParseSemVer parses a semver string like "1.2.3".
func ParseSemVer(s string) (SimplifiedSemVer, error) {
	if !semverPattern.MatchString(s) {
		return SimplifiedSemVer{}, NewValidationError(
			"MALFORMED_SEMVER",
			fmt.Sprintf("version must match pattern MAJOR.MINOR.PATCH: %q", s),
		)
	}

	parts := strings.Split(s, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])

	return SimplifiedSemVer{major: major, minor: minor, patch: patch}, nil
}

// Major returns the major version component.
func (v SimplifiedSemVer) Major() int { return v.major }

// Minor returns the minor version component.
func (v SimplifiedSemVer) Minor() int { return v.minor }

// Patch returns the patch version component.
func (v SimplifiedSemVer) Patch() int { return v.patch }

// String returns the version as "MAJOR.MINOR.PATCH".
func (v SimplifiedSemVer) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

// Compare returns -1, 0, or 1 comparing v to other.
func (v SimplifiedSemVer) Compare(other SimplifiedSemVer) int {
	if v.major != other.major {
		return cmpInt(v.major, other.major)
	}
	if v.minor != other.minor {
		return cmpInt(v.minor, other.minor)
	}
	return cmpInt(v.patch, other.patch)
}

// GreaterThan returns true if v > other.
func (v SimplifiedSemVer) GreaterThan(other SimplifiedSemVer) bool {
	return v.Compare(other) > 0
}

// Equal returns true if v == other.
func (v SimplifiedSemVer) Equal(other SimplifiedSemVer) bool {
	return v.Compare(other) == 0
}

// IsZero returns true if the version is uninitialized (0.0.0).
func (v SimplifiedSemVer) IsZero() bool {
	return v.major == 0 && v.minor == 0 && v.patch == 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
