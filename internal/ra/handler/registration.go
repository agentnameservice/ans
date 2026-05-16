package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// RegistrationHandler wires HTTP routes for POST /v2/ans/agents and
// the related verify-* endpoints.
type RegistrationHandler struct {
	svc *service.RegistrationService
}

// NewRegistrationHandler constructs a RegistrationHandler.
func NewRegistrationHandler(svc *service.RegistrationService) *RegistrationHandler {
	return &RegistrationHandler{svc: svc}
}

// registrationRequest is the V2 POST /v2/ans/agents body as JSON.
// The field names match spec/api-spec-v2.yaml.
//
// Server cert input follows the reference shape: exactly one of
// `serverCsrPEM` or `serverCertificatePEM` must be set (both or
// neither → 422). The CSR path routes through the RA's configured
// `ServerCertificateAuthority` port; the BYOC path routes through
// the certificate validator.
type registrationRequest struct {
	AgentDisplayName string `json:"agentDisplayName"`
	AgentDescription string `json:"agentDescription,omitempty"`
	// Version is optional under §3.2.0 (base-only registrations).
	// Required when identityCsrPEM is supplied; rejected when
	// identityCsrPEM is absent. The handler enforces both-or-neither.
	Version   string        `json:"version,omitempty"`
	AgentHost string        `json:"agentHost"`
	Endpoints []endpointDTO `json:"endpoints"`
	// IdentityCSRPEM is optional under §3.2.0. Required when Version
	// is supplied; rejected when Version is absent.
	IdentityCSRPEM            string `json:"identityCsrPEM,omitempty"`
	ServerCsrPEM              string `json:"serverCsrPEM,omitempty"`
	ServerCertificatePEM      string `json:"serverCertificatePEM,omitempty"`
	ServerCertificateChainPEM string `json:"serverCertificateChainPEM,omitempty"`

	// AgentCardContent is the optional ANS Trust Card body the
	// operator submits per ANS_SPEC.md §A.1. Modeled as
	// json.RawMessage so the bytes reach the service layer without
	// re-marshaling — JCS canonicalization is byte-precise, and any
	// round-trip through map[string]any would risk reordering or
	// number normalization that would shift the resulting digest.
	AgentCardContent json.RawMessage `json:"agentCardContent,omitempty"`

	// DNSRecordStyle selects which DNS record family the RA emits
	// for this registration. One of "consolidated" (default,
	// recommended), "legacy" (original `_ans` TXT shape), "both"
	// (transition union). Empty/missing → consolidated. Invalid
	// value rejected with 422 INVALID_DNS_RECORD_STYLE. See
	// ANS_SPEC.md §4.4.2 for record-shape semantics.
	DNSRecordStyle string `json:"dnsRecordStyle,omitempty"`
}

type endpointDTO struct {
	AgentURL         string        `json:"agentUrl"`
	MetadataURL      string        `json:"metaDataUrl,omitempty"`
	MetadataHash     string        `json:"metaDataHash,omitempty"`
	DocumentationURL string        `json:"documentationUrl,omitempty"`
	Protocol         string        `json:"protocol"`
	Functions        []functionDTO `json:"functions,omitempty"`
	Transports       []string      `json:"transports,omitempty"`
}

type functionDTO struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// registrationPendingResponse mirrors the V2 spec's RegistrationPending
// schema (spec/api-spec-v2.yaml §1167). Field names and optionality
// match the spec exactly — no extensions. `challenges` holds ACME
// challenges needed to drive verify-acme; ans emits DNS_01 only.
type registrationPendingResponse struct {
	AgentID    string         `json:"agentId"`
	Status     string         `json:"status"`
	AnsName    string         `json:"ansName"`
	Challenges []challengeDTO `json:"challenges,omitempty"`
	DNSRecords []dnsRecordDTO `json:"dnsRecords"`
	NextSteps  []nextStepDTO  `json:"nextSteps"`
	ExpiresAt  string         `json:"expiresAt,omitempty"`
	Links      []linkDTO      `json:"links,omitempty"`
}

type dnsRecordDTO struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Purpose  string `json:"purpose"`
	Required bool   `json:"required"`
	TTL      int    `json:"ttl"`
}

// challengeDTO mirrors the V2 ChallengeInfo schema. ans emits DNS_01
// only per the documented no-HTTP-01 deviation.
type challengeDTO struct {
	Type      string                 `json:"type"`
	Token     string                 `json:"token"`
	DNSRecord *challengeDNSRecordDTO `json:"dnsRecord,omitempty"`
	ExpiresAt string                 `json:"expiresAt,omitempty"`
}

type challengeDNSRecordDTO struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type nextStepDTO struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	Endpoint    string `json:"endpoint,omitempty"`
}

type linkDTO struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// Register is the handler for POST /v2/ans/agents.
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Limit body size to prevent memory exhaustion from malicious clients.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MiB

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("BAD_JSON", "invalid request body: "+err.Error()))
		return
	}

	// Extract identity from context.
	id, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		WriteError(w, domain.NewUnauthorizedError("NO_IDENTITY", "authentication required"))
		return
	}

	ansName, err := resolveAnsNameForRegister(&req)
	if err != nil {
		WriteError(w, err)
		return
	}

	eps, err := mapEndpointsFromDTO(req.Endpoints)
	if err != nil {
		WriteError(w, err)
		return
	}

	resp, err := h.svc.RegisterAgent(r.Context(), service.RegisterRequest{
		OwnerID:                   id.Subject,
		AnsName:                   ansName,
		AgentHost:                 req.AgentHost,
		DisplayName:               req.AgentDisplayName,
		Description:               req.AgentDescription,
		Endpoints:                 eps,
		IdentityCSRPEM:            req.IdentityCSRPEM,
		ServerCsrPEM:              req.ServerCsrPEM,
		ServerCertificatePEM:      req.ServerCertificatePEM,
		ServerCertificateChainPEM: req.ServerCertificateChainPEM,
		AgentCardContent:          []byte(req.AgentCardContent),
		DNSRecordStyle:            domain.DNSRecordStyle(req.DNSRecordStyle),
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusAccepted, mapRegistrationResponse(resp, r))
}

// mapEndpointsFromDTO converts the incoming JSON endpoints to the
// domain types, returning a validation error on malformed input.
func mapEndpointsFromDTO(dtos []endpointDTO) ([]domain.AgentEndpoint, error) {
	if len(dtos) == 0 {
		return nil, domain.NewValidationError("MISSING_ENDPOINTS", "at least one endpoint is required")
	}
	out := make([]domain.AgentEndpoint, len(dtos))
	for i, d := range dtos {
		proto, err := domain.ParseProtocol(d.Protocol)
		if err != nil {
			return nil, err
		}
		transports := make([]domain.Transport, 0, len(d.Transports))
		for _, t := range d.Transports {
			tt, err := domain.ParseTransport(t)
			if err != nil {
				return nil, err
			}
			transports = append(transports, tt)
		}
		funcs := make([]domain.AgentFunction, len(d.Functions))
		for j, f := range d.Functions {
			funcs[j] = domain.AgentFunction{ID: f.ID, Name: f.Name, Tags: f.Tags}
		}
		out[i] = domain.AgentEndpoint{
			Protocol:         proto,
			AgentURL:         d.AgentURL,
			MetadataURL:      d.MetadataURL,
			DocumentationURL: d.DocumentationURL,
			Functions:        funcs,
			Transports:       transports,
			MetadataHash:     d.MetadataHash,
		}
	}
	return out, nil
}

func mapRegistrationResponse(resp *service.RegisterResponse, r *http.Request) *registrationPendingResponse {
	dnsRecords := make([]dnsRecordDTO, len(resp.DNSRecords))
	for i, rec := range resp.DNSRecords {
		dnsRecords[i] = dnsRecordDTO{
			Name:     rec.Name,
			Type:     string(rec.Type),
			Value:    rec.Value,
			Purpose:  string(rec.Purpose),
			Required: rec.Required,
			TTL:      rec.TTL,
		}
	}
	base := schemeOf(r) + "://" + r.Host + "/v2/ans/agents/" + resp.Registration.AgentID

	// Register-time next-steps reflect the deferred-cert flow: certs
	// only issue once verify-acme proves domain control, so the only
	// step the operator can take right now is publish the ACME
	// challenge TXT and call verify-acme. Production DNS records
	// (TRUST/BADGE/DISCOVERY/TLSA) only materialize on the
	// verify-acme 202, where they appear paired with VERIFY_DNS as
	// the next step.
	return &registrationPendingResponse{
		AgentID:    resp.Registration.AgentID,
		Status:     string(resp.Registration.Status),
		AnsName:    resp.Registration.AnsName.String(),
		Challenges: buildRegistrationChallenges(resp.Registration),
		DNSRecords: dnsRecords,
		NextSteps: []nextStepDTO{
			{Action: "CONFIGURE_DNS",
				Description: "Publish the ACME DNS-01 challenge TXT record listed in challenges[]",
				Endpoint:    base + "/verify-acme"},
			{Action: "VALIDATE_DOMAIN",
				Description: "Call POST /v2/ans/agents/{agentId}/verify-acme once the challenge record is live",
				Endpoint:    base + "/verify-acme"},
		},
		ExpiresAt: rfc3339Zero(resp.Registration.ACMEChallenge.ExpiresAt),
		Links: []linkDTO{
			{Rel: "self", Href: base},
		},
	}
}

// buildRegistrationChallenges builds the ChallengeInfo array for the
// V2 RegistrationPending response. ans emits DNS_01 only. Named
// distinctly from renewalmap.go's renewal-specific `buildChallenges`
// to avoid collision.
func buildRegistrationChallenges(reg *domain.AgentRegistration) []challengeDTO {
	if reg.ACMEChallenge.IsZero() {
		return nil
	}
	return []challengeDTO{{
		Type:  "DNS_01",
		Token: reg.ACMEChallenge.DNS01Token,
		DNSRecord: &challengeDNSRecordDTO{
			Name:  "_acme-challenge." + reg.FQDN(),
			Type:  "TXT",
			Value: reg.ACMEChallenge.DNS01Token,
		},
		ExpiresAt: rfc3339Zero(reg.ACMEChallenge.ExpiresAt),
	}}
}

// schemeOf returns "https" if the request was served over TLS or
// behind a proxy that set X-Forwarded-Proto, otherwise "http".
func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// silence "imported and not used" if handlers evolve.
var _ = errors.New

// resolveAnsNameForRegister translates the request's optional version
// and Identity CSR fields into a canonical AnsName per ANS_SPEC.md
// §3.2.0 + §1.8.
//
// Returns:
//   - non-zero AnsName when both version + identityCsrPEM are
//     supplied (versioned registration);
//   - zero-value AnsName when both are absent (base-only);
//   - validation error when one is supplied without the other
//     (VERSIONED_REQUIRES_IDENTITY_CSR or BASE_ONLY_REJECTS_IDENTITY_CSR).
func resolveAnsNameForRegister(req *registrationRequest) (domain.AnsName, error) {
	versionGiven := strings.TrimSpace(req.Version) != ""
	csrGiven := strings.TrimSpace(req.IdentityCSRPEM) != ""
	switch {
	case versionGiven && !csrGiven:
		return domain.AnsName{}, domain.NewValidationError(
			"VERSIONED_REQUIRES_IDENTITY_CSR",
			"version submitted without identityCsrPEM: versioned registrations require both",
		)
	case !versionGiven && csrGiven:
		return domain.AnsName{}, domain.NewValidationError(
			"BASE_ONLY_REJECTS_IDENTITY_CSR",
			"identityCsrPEM submitted without a version: base-only registrations cannot have an Identity Certificate",
		)
	case !versionGiven && !csrGiven:
		// Base-only path: zero-value AnsName signals to the service.
		return domain.AnsName{}, nil
	}
	semver, err := domain.ParseSemVer(req.Version)
	if err != nil {
		return domain.AnsName{}, err
	}
	return domain.NewAnsName(semver, req.AgentHost)
}
