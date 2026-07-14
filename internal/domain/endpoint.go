package domain

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxFunctionTags       = 5
	maxTagLength          = 20
	maxFunctionIDLength   = 64
	maxFunctionNameLength = 64
	// maxMetadataURLLength bounds the operator-supplied metadataUrl. It
	// is emitted verbatim as the DNSAID `cap` SvcParam and embedded in the
	// signed TL attestation, so an unbounded value would bloat the
	// append-only log and produce an unservable DNS record.
	maxMetadataURLLength = 2048
)

var metadataHashPattern = regexp.MustCompile(`^SHA256:[a-f0-9]{64}$`)

// AgentFunction represents a function provided by an agent endpoint.
type AgentFunction struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// Validate checks that the function has valid fields.
func (f AgentFunction) Validate() error {
	if len(f.ID) > maxFunctionIDLength {
		return NewValidationError(
			"INVALID_FUNCTION",
			fmt.Sprintf("function id length %d exceeds %d characters", len(f.ID), maxFunctionIDLength),
		)
	}
	if strings.TrimSpace(f.ID) == "" {
		return NewValidationError("INVALID_FUNCTION", "function id cannot be blank")
	}

	if len(f.Name) > maxFunctionNameLength {
		return NewValidationError(
			"INVALID_FUNCTION",
			fmt.Sprintf("function name length %d exceeds %d characters", len(f.Name), maxFunctionNameLength),
		)
	}
	if strings.TrimSpace(f.Name) == "" {
		return NewValidationError("INVALID_FUNCTION", "function name cannot be blank")
	}

	for _, tag := range f.Tags {
		if len(tag) > maxTagLength {
			return NewValidationError(
				"INVALID_FUNCTION",
				fmt.Sprintf("function tag %q exceeds %d characters", tag, maxTagLength),
			)
		}
	}
	if len(f.Tags) > maxFunctionTags {
		return NewValidationError(
			"INVALID_FUNCTION",
			fmt.Sprintf("function has %d tags, maximum is %d", len(f.Tags), maxFunctionTags),
		)
	}
	return nil
}

// AgentEndpoint represents a single protocol endpoint for an agent.
type AgentEndpoint struct {
	Protocol         Protocol        `json:"protocol"`
	AgentURL         string          `json:"agentUrl"`
	MetadataURL      string          `json:"metadataUrl,omitempty"`
	DocumentationURL string          `json:"documentationUrl,omitempty"`
	Functions        []AgentFunction `json:"functions,omitempty"`
	Transports       []Transport     `json:"transports,omitempty"`
	MetadataHash     string          `json:"metadataHash,omitempty"`
}

// Validate checks that the endpoint has valid fields.
func (e AgentEndpoint) Validate() error {
	if !e.Protocol.IsValid() {
		return NewValidationError("INVALID_ENDPOINT", fmt.Sprintf("invalid protocol: %q", e.Protocol))
	}

	if err := validateURL(e.AgentURL, "agentUrl"); err != nil {
		return err
	}

	if e.MetadataURL != "" {
		if err := validateMetadataURL(e.MetadataURL); err != nil {
			return err
		}
	}

	if e.DocumentationURL != "" {
		if err := validateURL(e.DocumentationURL, "documentationUrl"); err != nil {
			return err
		}
	}

	if e.MetadataHash != "" {
		if e.MetadataURL == "" {
			return NewValidationError(
				"INVALID_ENDPOINT",
				"metadataHash requires metadataUrl to be set",
			)
		}
		if !metadataHashPattern.MatchString(e.MetadataHash) {
			return NewValidationError(
				"INVALID_ENDPOINT",
				fmt.Sprintf("metadataHash must match SHA256:<64 hex chars>: %q", e.MetadataHash),
			)
		}
	}

	// Check for duplicate function IDs.
	seen := make(map[string]bool, len(e.Functions))
	for _, fn := range e.Functions {
		if err := fn.Validate(); err != nil {
			return err
		}
		if seen[fn.ID] {
			return NewValidationError(
				"INVALID_ENDPOINT",
				fmt.Sprintf("duplicate function id: %q", fn.ID),
			)
		}
		seen[fn.ID] = true
	}

	for _, t := range e.Transports {
		if !t.IsValid() {
			return NewValidationError(
				"INVALID_ENDPOINT",
				fmt.Sprintf("invalid transport: %q", t),
			)
		}
	}

	return nil
}

// ValidateHostMatch checks that the endpoint URL's hostname matches the expected FQDN.
func (e AgentEndpoint) ValidateHostMatch(expectedFQDN string) error {
	parsed, err := url.Parse(e.AgentURL)
	if err != nil {
		return NewValidationError(
			"INVALID_ENDPOINT",
			fmt.Sprintf("cannot parse agentUrl: %v", err),
		)
	}

	hostname := strings.ToLower(parsed.Hostname())
	expected := strings.ToLower(expectedFQDN)

	if hostname != expected {
		return NewValidationError(
			"ENDPOINT_HOST_MISMATCH",
			fmt.Sprintf("endpoint hostname %q does not match agent FQDN %q", hostname, expected),
		)
	}

	return nil
}

// AgentEndpoints is a validated collection of endpoints for an agent.
type AgentEndpoints struct {
	AgentID   string          `json:"agentId"`
	Endpoints []AgentEndpoint `json:"endpoints"`
}

// Validate checks the endpoint collection is valid.
func (ae AgentEndpoints) Validate(expectedFQDN string) error {
	if len(ae.Endpoints) == 0 {
		return NewValidationError("INVALID_ENDPOINTS", "at least one endpoint is required")
	}

	// Check for duplicate protocol+URL pairs.
	type key struct {
		protocol Protocol
		url      string
	}
	seen := make(map[key]bool, len(ae.Endpoints))
	protocols := make(map[Protocol]bool, len(ae.Endpoints))

	for _, ep := range ae.Endpoints {
		if err := ep.Validate(); err != nil {
			return err
		}

		if err := ep.ValidateHostMatch(expectedFQDN); err != nil {
			return err
		}

		k := key{protocol: ep.Protocol, url: ep.AgentURL}
		if seen[k] {
			return NewValidationError(
				"DUPLICATE_ENDPOINT",
				fmt.Sprintf("duplicate endpoint: protocol=%s url=%s", ep.Protocol, ep.AgentURL),
			)
		}
		seen[k] = true

		if protocols[ep.Protocol] {
			return NewValidationError(
				"DUPLICATE_PROTOCOL",
				fmt.Sprintf("duplicate protocol: %s", ep.Protocol),
			)
		}
		protocols[ep.Protocol] = true
	}

	return nil
}

func validateURL(rawURL, fieldName string) error {
	if strings.TrimSpace(rawURL) == "" {
		return NewValidationError(
			"INVALID_ENDPOINT",
			fmt.Sprintf("%s cannot be empty", fieldName),
		)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return NewValidationError(
			"INVALID_ENDPOINT",
			fmt.Sprintf("%s is not a valid URL: %q", fieldName, rawURL),
		)
	}
	// url.Parse accepts any positive integer port string. An
	// out-of-range port (0, 99999, or a 64-bit overflow value) would
	// flow into the SVCB `port=` SvcParam and the TLSA owner name
	// (`_<port>._tcp.`), producing a record set no DNS provider will
	// accept — the operator would strand their own agent in
	// PENDING_DNS with an unexplainable verify-dns mismatch. Reject it
	// loudly here at the registration boundary instead.
	if p := parsed.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return NewValidationError(
				"INVALID_ENDPOINT",
				fmt.Sprintf("%s port %q is outside the valid range 1-65535", fieldName, p),
			)
		}
	}
	return nil
}

// validateMetadataURL enforces the constraints metadataUrl must satisfy
// to be safely emitted as the DNSAID `cap` SvcParam (key65400) and
// digested by `cap-sha256`: a well-formed https URL, bounded length, and
// free of characters the SVCB presentation format escapes. The verifier
// compares the expected record against the live record by splitting on
// whitespace (strings.Fields) and first `=`, so a metadataUrl carrying a
// space, quote, backslash, semicolon, or non-printable byte would either
// inject a bogus SvcParam into the producer-signed attestation or break
// verify-dns and strand the agent in PENDING_DNS — the same class of
// self-inflicted failure validateURL already guards for out-of-range
// ports. Reject it loudly at the registration boundary instead.
func validateMetadataURL(rawURL string) error {
	if err := validateURL(rawURL, "metadataUrl"); err != nil {
		return err
	}
	// validateURL guarantees a successful parse, so the error is
	// unreachable here.
	u, _ := url.Parse(rawURL)
	if u.Scheme != "https" {
		return NewValidationError("INVALID_ENDPOINT", "metadataUrl must be an https URL")
	}
	if len(rawURL) > maxMetadataURLLength {
		return NewValidationError(
			"INVALID_ENDPOINT",
			fmt.Sprintf("metadataUrl exceeds maximum length of %d characters", maxMetadataURLLength),
		)
	}
	// The raw-string check guards the `cap` SvcParam (key65400), emitted
	// verbatim from rawURL. The DNSAID well-known SvcParam (key65409) is
	// instead derived from u.Path, which url.Parse has percent-DECODED —
	// so `%20`→space and `%3B`→`;` clear a raw-only check, then split the
	// SvcParam on the verifier's strings.Fields and strand the agent in
	// PENDING_DNS. Both surfaces must be presentation-safe, so check the
	// decoded path as well.
	if containsSVCBUnsafe(rawURL) || containsSVCBUnsafe(u.Path) {
		return NewValidationError(
			"INVALID_ENDPOINT",
			"metadataUrl must not contain whitespace, quotes, or other characters that require SVCB presentation escaping",
		)
	}
	return nil
}

// containsSVCBUnsafe reports whether s carries any byte miekg/dns escapes
// when rendering an SVCB SvcParam — whitespace, double quote, backslash,
// semicolon, or a non-printable ASCII rune. Both the raw metadataUrl and
// its percent-decoded path must clear it: the raw form feeds the `cap`
// SvcParam, the decoded path feeds the well-known SvcParam.
func containsSVCBUnsafe(s string) bool {
	return strings.ContainsAny(s, " \t\r\n\f\v\"\\;") || hasNonPrintableASCII(s)
}

// hasNonPrintableASCII reports whether s contains any rune outside the
// printable ASCII range (0x20–0x7e). It complements the explicit
// ContainsAny blocklist in validateMetadataURL: together they reject
// exactly the bytes miekg/dns escapes when rendering an SVCB SvcParam,
// keeping the published value byte-identical to what the verifier
// observes.
func hasNonPrintableASCII(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return true
		}
	}
	return false
}
