package handler

import (
	"encoding/json"
	"net/http"

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
// `ServerCertificateIssuer` port; the BYOC path routes through
// the certificate validator.
type registrationRequest struct {
	AgentDisplayName          string        `json:"agentDisplayName"`
	AgentDescription          string        `json:"agentDescription,omitempty"`
	Version                   string        `json:"version"`
	AgentHost                 string        `json:"agentHost"`
	Endpoints                 []endpointDTO `json:"endpoints"`
	IdentityCSRPEM            string        `json:"identityCsrPEM"`
	ServerCsrPEM              string        `json:"serverCsrPEM,omitempty"`
	ServerCertificatePEM      string        `json:"serverCertificatePEM,omitempty"`
	ServerCertificateChainPEM string        `json:"serverCertificateChainPEM,omitempty"`

	// DiscoveryProfiles is the set of DNS record families the RA emits
	// for this registration. Each element is one of "ANS_SVCB" or
	// "ANS_TXT". Typical values: ["ANS_SVCB"] (default, recommended),
	// ["ANS_TXT"], or ["ANS_SVCB", "ANS_TXT"] (transition union).
	// Empty/missing → ["ANS_SVCB"]. Any invalid element rejected
	// with 422 INVALID_DISCOVERY_PROFILE. See ANS_SPEC.md §4.4.2.
	DiscoveryProfiles []string `json:"discoveryProfiles,omitempty"`
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
// match the spec exactly — no extensions. `challenges` relays the
// certificate order's domain-control challenges (DNS_01 and HTTP_01);
// the owner publishes whichever artifact is easier and ANS verifies
// it at verify-acme.
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

// challengeDTO mirrors the V2 ChallengeInfo schema: type, token,
// keyAuthorization, dnsRecord, httpPath, expiresAt. keyAuthorization
// is populated when the issuing provider binds the token to its
// account key (ACME); self-issued challenges omit it.
type challengeDTO struct {
	Type             string                 `json:"type"`
	Token            string                 `json:"token"`
	KeyAuthorization string                 `json:"keyAuthorization,omitempty"`
	DNSRecord        *challengeDNSRecordDTO `json:"dnsRecord,omitempty"`
	HTTPPath         string                 `json:"httpPath,omitempty"`
	ExpiresAt        string                 `json:"expiresAt,omitempty"`
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

	// Parse version + host into an AnsName.
	semver, err := domain.ParseSemVer(req.Version)
	if err != nil {
		WriteError(w, err)
		return
	}
	ansName, err := domain.NewAnsName(semver, req.AgentHost)
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
		DisplayName:               req.AgentDisplayName,
		Description:               req.AgentDescription,
		Endpoints:                 eps,
		IdentityCSRPEM:            req.IdentityCSRPEM,
		ServerCsrPEM:              req.ServerCsrPEM,
		ServerCertificatePEM:      req.ServerCertificatePEM,
		ServerCertificateChainPEM: req.ServerCertificateChainPEM,
		DiscoveryProfiles:         toDomainDiscoveryProfiles(req.DiscoveryProfiles),
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusAccepted, mapRegistrationResponse(resp, r))
}

// toDomainDiscoveryProfiles converts the wire []string into the typed
// domain slice. nil (field omitted in the JSON request) flows through
// as nil and a non-nil empty slice (explicit `"discoveryProfiles": []`)
// flows through as an empty non-nil []DiscoveryProfile; the service
// layer normalizes both to DefaultDiscoveryProfiles(), so the
// distinction no longer changes the outcome. Per-element validity and
// duplicate deduplication live in applyDiscoveryProfiles.
func toDomainDiscoveryProfiles(raw []string) []domain.DiscoveryProfile {
	if raw == nil {
		return nil
	}
	out := make([]domain.DiscoveryProfile, len(raw))
	for i, s := range raw {
		out[i] = domain.DiscoveryProfile(s)
	}
	return out
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
	// step the operator can take right now is publish a challenge
	// artifact and call verify-acme. Production DNS records
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
				Description: "Publish one challenge artifact from challenges[]: the DNS-01 TXT record, or the HTTP-01 resource at its httpPath",
				Endpoint:    base + "/verify-acme"},
			{Action: "VALIDATE_DOMAIN",
				Description: "Call POST /v2/ans/agents/{agentId}/verify-acme once the challenge artifact is live",
				Endpoint:    base + "/verify-acme"},
		},
		ExpiresAt: rfc3339Zero(resp.Registration.CertOrder.ExpiresAt),
		Links: []linkDTO{
			{Rel: "self", Href: base},
		},
	}
}

// buildRegistrationChallenges relays the certificate order's
// challenge set as the ChallengeInfo array for the V2
// RegistrationPending response. The entries are the provider's own
// challenges, verbatim — for an external ACME provider that means its
// token, key authorization, and computed DNS digest; for the
// in-process CA the self-issued tokens. Named distinctly from
// renewalmap.go's renewal-specific builder to avoid collision.
//
// Returns nil (omitted on the wire) when no order is present — e.g.
// a registration pre-dating order persistence.
func buildRegistrationChallenges(reg *domain.AgentRegistration) []challengeDTO {
	if reg.CertOrder.IsZero() {
		return nil
	}
	expiresAt := rfc3339Zero(reg.CertOrder.ExpiresAt)
	out := make([]challengeDTO, 0, len(reg.CertOrder.Challenges))
	for _, ch := range reg.CertOrder.Challenges {
		dto := challengeDTO{
			Type:             string(ch.Type),
			Token:            ch.Token,
			KeyAuthorization: ch.KeyAuthorization,
			ExpiresAt:        expiresAt,
		}
		switch ch.Type {
		case domain.ChallengeTypeDNS01:
			dto.DNSRecord = &challengeDNSRecordDTO{
				Name:  ch.EffectiveDNSRecordName(reg.FQDN()),
				Type:  "TXT",
				Value: ch.EffectiveDNSRecordValue(),
			}
		case domain.ChallengeTypeHTTP01:
			dto.HTTPPath = ch.EffectiveHTTPPath()
		}
		out = append(out, dto)
	}
	return out
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
