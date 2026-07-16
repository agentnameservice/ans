package domain

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	ansProtocolPrefix = "ans://"
	maxHostnameLength = 253
	maxLabelLength    = 63
)

// RFC 1123 hostname label: alphanumeric, hyphens allowed (not at start/end), max 63 chars.
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// AnsName represents an Agent Name Service name in the format:
// ans://v{MAJOR.MINOR.PATCH}.{agentHost}
//
// Example: ans://v1.2.0.myagent.example.com
type AnsName struct {
	version   SimplifiedSemVer
	agentHost string // lowercase FQDN
}

// NewAnsName creates an AnsName from a version and agent host.
func NewAnsName(version SimplifiedSemVer, agentHost string) (AnsName, error) {
	host := strings.ToLower(strings.TrimSpace(agentHost))
	if err := validateAgentHost(host); err != nil {
		return AnsName{}, err
	}
	return AnsName{version: version, agentHost: host}, nil
}

// ParseAnsName parses an ANS name string like "ans://v1.2.0.myagent.example.com".
func ParseAnsName(s string) (AnsName, error) {
	s = strings.TrimSpace(s)

	if !strings.HasPrefix(s, ansProtocolPrefix) {
		return AnsName{}, NewValidationError(
			"INVALID_ANS_PROTOCOL",
			fmt.Sprintf("ANS name must start with %q: %q", ansProtocolPrefix, s),
		)
	}

	remainder := s[len(ansProtocolPrefix):]

	if !strings.HasPrefix(remainder, "v") {
		return AnsName{}, NewValidationError(
			"INVALID_ANS_VERSION",
			fmt.Sprintf("ANS name version segment must start with 'v': %q", s),
		)
	}

	// Find where the version ends and the host begins.
	// Format: v{MAJOR.MINOR.PATCH}.{host}
	// The version has exactly two dots, then the third dot separates version from host.
	remainder = remainder[1:] // strip the 'v'

	dotCount := 0
	hostStart := -1
	for i, ch := range remainder {
		if ch == '.' {
			dotCount++
			if dotCount == 3 {
				hostStart = i + 1
				break
			}
		}
	}

	if hostStart < 0 || hostStart >= len(remainder) {
		return AnsName{}, NewValidationError(
			"MALFORMED_ANS_NAME",
			fmt.Sprintf("ANS name must have format ans://v{M.N.P}.{host}: %q", s),
		)
	}

	versionStr := remainder[:hostStart-1] // everything before the third dot
	hostStr := remainder[hostStart:]

	version, err := ParseSemVer(versionStr)
	if err != nil {
		return AnsName{}, NewValidationError(
			"INVALID_ANS_VERSION",
			fmt.Sprintf("invalid version in ANS name %q: %v", s, err),
		)
	}

	return NewAnsName(version, hostStr)
}

// Version returns the semantic version component.
func (n AnsName) Version() SimplifiedSemVer { return n.version }

// VersionSegment returns the ANS-2 version segment: the v-prefixed
// semver form ("v1.2.0") that appears as the leading hostname label of
// the ANS name and as the `version=` value in the `_ans`/`_ans-badge`
// TXT records (ANS-3 §6.3, ans-txt profile §2).
func (n AnsName) VersionSegment() string { return "v" + n.version.String() }

// AgentHost returns the FQDN component (lowercase).
func (n AnsName) AgentHost() string { return n.agentHost }

// FQDN is an alias for AgentHost.
func (n AnsName) FQDN() string { return n.agentHost }

// String returns the full ANS name: ans://v1.2.0.myagent.example.com.
func (n AnsName) String() string {
	return fmt.Sprintf("%s%s.%s", ansProtocolPrefix, n.VersionSegment(), n.agentHost)
}

// IsZero returns true if the AnsName is uninitialized.
func (n AnsName) IsZero() bool {
	return n.agentHost == "" && n.version.IsZero()
}

// validateAgentHost validates a hostname per RFC 1123.
func validateAgentHost(host string) error {
	if host == "" {
		return NewValidationError("INVALID_AGENT_HOST", "agent host cannot be empty")
	}

	if len(host) > maxHostnameLength {
		return NewValidationError(
			"AGENT_HOST_TOO_LONG",
			fmt.Sprintf("agent host exceeds %d characters: %d", maxHostnameLength, len(host)),
		)
	}

	// Reject IP literals. An ANS name binds a DNS hostname; an IP
	// (e.g. "169.254.169.254" or an IPv6 literal) is never a valid
	// agent host, and accepting one would let a registrant point the
	// HTTP-01 challenge gate at an internal address. The label checks
	// below would otherwise pass a dotted-quad IPv4 as four numeric
	// "labels".
	if net.ParseIP(host) != nil {
		return NewValidationError(
			"INVALID_AGENT_HOST",
			fmt.Sprintf("agent host must be a DNS hostname, not an IP address: %q", host),
		)
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return NewValidationError(
			"INVALID_AGENT_HOST",
			fmt.Sprintf("agent host must have at least two labels (e.g., example.com): %q", host),
		)
	}

	for _, label := range labels {
		if len(label) > maxLabelLength {
			return NewValidationError(
				"AGENT_HOST_LABEL_TOO_LONG",
				fmt.Sprintf("label %q exceeds %d characters", label, maxLabelLength),
			)
		}
		if !labelPattern.MatchString(label) {
			return NewValidationError(
				"INVALID_AGENT_HOST",
				fmt.Sprintf("label %q is not a valid DNS label (RFC 1123)", label),
			)
		}
	}

	return nil
}
