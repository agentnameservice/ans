package domain

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxFunctionTags = 20
	maxTagLength    = 20
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
	if strings.TrimSpace(f.ID) == "" {
		return NewValidationError("INVALID_FUNCTION", "function id cannot be blank")
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
		if err := validateURL(e.MetadataURL, "metadataUrl"); err != nil {
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
	return nil
}
