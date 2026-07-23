package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/auth"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// V1 RA handlers. Byte-for-byte DTO parity with the reference RA's
// `/v1/agents/*` surface (see the reference V1 API spec).
//
// Design:
//
//   - Request/response DTOs are defined in this file and match the
//     reference spec exactly — field names, optional vs required,
//     enum values. A V1 SDK compiled against the reference will
//     decode our responses without a single tag fix.
//   - The handlers share business logic with V2 via the same
//     `*service.RegistrationService`. The service-layer branch
//     between V1 and V2 happens only at the outbox-emit step
//     (different envelope shape, different TL ingest lane — see
//     `internal/ra/service/v1event.go`).
//   - TL leaf emission on POST /register is deliberately deferred to
//     the verify-dns / verify-acme handlers. The V1 reference only
//     writes the AGENT_REGISTERED leaf when the full registration
//     completes (domain validated + certs issued + DNS live); the
//     initial POST returns a 202 with pending state and emits
//     nothing to the TL.
//
// ans deviations from the reference that apply here:
//
//   - **DNS-01-only on the V1 wire.** The V1 `challenges` array
//     carries a single DNS_01 entry. The verify-acme gate itself
//     accepts either artifact (DNS-01 TXT or HTTP-01 resource) —
//     HTTP-01 challenge info is simply not relayed on this lane;
//     V2 surfaces both.
//
// Server-cert handling matches the reference byte-for-byte: either
// `serverCsrPEM` (→ the order is finalized via the configured
// `ServerCertificateIssuer` port) or `serverCertificatePEM` + chain
// (BYOC path). Exactly one must be set.

// V1RegistrationHandler wires HTTP routes for the V1 `/v1/agents/*`
// registration + detail surface.
type V1RegistrationHandler struct {
	responder
	svc *service.RegistrationService
}

// NewV1RegistrationHandler constructs a V1RegistrationHandler.
func NewV1RegistrationHandler(svc *service.RegistrationService, logger zerolog.Logger) *V1RegistrationHandler {
	return &V1RegistrationHandler{responder: newResponder(logger), svc: svc}
}

// v1RegistrationRequest mirrors the `AgentRegistrationRequest`
// schema in the reference V1 API spec. Field names and JSON tags
// match byte-for-byte. Like the reference, exactly one of
// `serverCsrPEM` / `serverCertificatePEM` must be set; both or
// neither is 422.
type v1RegistrationRequest struct {
	AgentDisplayName          string          `json:"agentDisplayName"`
	AgentDescription          string          `json:"agentDescription,omitempty"`
	Version                   string          `json:"version"`
	AgentHost                 string          `json:"agentHost"`
	Endpoints                 []v1EndpointDTO `json:"endpoints"`
	ServerCSRPEM              string          `json:"serverCsrPEM,omitempty"`
	ServerCertificatePEM      string          `json:"serverCertificatePEM,omitempty"`
	ServerCertificateChainPEM string          `json:"serverCertificateChainPEM,omitempty"`
	IdentityCSRPEM            string          `json:"identityCsrPEM"`
}

// v1EndpointDTO mirrors the reference `AgentEndpoint` object. Shape
// is identical to V2's `endpointDTO`; kept as a distinct type in
// this package to keep V1 DTOs self-contained and allow independent
// evolution.
type v1EndpointDTO struct {
	AgentURL         string          `json:"agentUrl"`
	MetadataURL      string          `json:"metaDataUrl,omitempty"`
	MetadataHash     string          `json:"metaDataHash,omitempty"`
	DocumentationURL string          `json:"documentationUrl,omitempty"`
	Protocol         string          `json:"protocol"`
	Functions        []v1FunctionDTO `json:"functions,omitempty"`
	Transports       []string        `json:"transports,omitempty"`
}

// v1FunctionDTO is the nested agent-function descriptor.
type v1FunctionDTO struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// v1RegistrationPendingResponse mirrors the reference
// `RegistrationPending` schema
// (hack/ans-registry-poc/ans-api-spec/api-spec.yaml:1574). Byte-for-byte
// parity, modulo the documented DNS-01-only deviation (`challenges[]`
// carries a single DNS_01 entry, no HTTP_01).
type v1RegistrationPendingResponse struct {
	AgentID    string           `json:"agentId"`
	Status     string           `json:"status"`
	AnsName    string           `json:"ansName"`
	Challenges []v1ChallengeDTO `json:"challenges,omitempty"`
	DNSRecords []v1DNSRecordDTO `json:"dnsRecords"`
	NextSteps  []v1NextStepDTO  `json:"nextSteps"`
	ExpiresAt  string           `json:"expiresAt,omitempty"`
	Links      []v1LinkDTO      `json:"links,omitempty"`
}

type v1DNSRecordDTO struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Purpose  string `json:"purpose"`
	Required bool   `json:"required"`
	TTL      int    `json:"ttl"`
}

// v1ChallengeDTO mirrors the reference `ChallengeInfo` schema
// (api-spec.yaml:1628). ans emits DNS_01 only.
type v1ChallengeDTO struct {
	Type      string                   `json:"type"`
	Token     string                   `json:"token"`
	DNSRecord *v1ChallengeDNSRecordDTO `json:"dnsRecord,omitempty"`
	ExpiresAt string                   `json:"expiresAt,omitempty"`
}

// v1ChallengeDNSRecordDTO is the nested DNS record referenced by a
// DNS_01 challenge.
type v1ChallengeDNSRecordDTO struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type v1NextStepDTO struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	Endpoint    string `json:"endpoint,omitempty"`
}

type v1LinkDTO struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// v1AgentDetailResponse mirrors the reference `Agent` schema — a read
// view of the aggregate for GET /v1/agents/{agentId}. Non-terminal
// statuses (PENDING_VALIDATION, PENDING_DNS) surface a
// `registrationPending` block with the challenges + dnsRecords the
// operator still needs to act on; ACTIVE/REVOKED agents omit it.
type v1AgentDetailResponse struct {
	AgentID               string                         `json:"agentId"`
	AnsName               string                         `json:"ansName"`
	AgentDisplayName      string                         `json:"agentDisplayName"`
	AgentDescription      string                         `json:"agentDescription,omitempty"`
	Version               string                         `json:"version"`
	AgentHost             string                         `json:"agentHost"`
	AgentStatus           string                         `json:"agentStatus"`
	Endpoints             []v1EndpointDTO                `json:"endpoints"`
	RegistrationTimestamp string                         `json:"registrationTimestamp"`
	LastRenewalTimestamp  string                         `json:"lastRenewalTimestamp,omitempty"`
	RegistrationPending   *v1RegistrationPendingResponse `json:"registrationPending,omitempty"`
	Links                 []v1LinkDTO                    `json:"links,omitempty"`
}

// Register is the handler for POST /v1/agents/register. Produces an
// AgentRegistrationPending response (202). Does NOT emit a TL event —
// the V1 AGENT_REGISTERED leaf is written only once the registration
// completes (domain validated + DNS live), which happens in the
// verify-dns / verify-acme handlers.
func (h *V1RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	var req v1RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, domain.NewValidationError("BAD_JSON", "invalid request body: "+err.Error()))
		return
	}

	id, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		h.writeError(w, domain.NewUnauthorizedError("NO_IDENTITY", "authentication required"))
		return
	}

	semver, err := domain.ParseSemVer(req.Version)
	if err != nil {
		h.writeError(w, err)
		return
	}
	ansName, err := domain.NewAnsName(semver, req.AgentHost)
	if err != nil {
		h.writeError(w, err)
		return
	}

	eps, err := mapV1EndpointsFromDTO(req.Endpoints)
	if err != nil {
		h.writeError(w, err)
		return
	}

	resp, err := h.svc.RegisterAgent(r.Context(), service.RegisterRequest{
		OwnerID:                   id.Subject,
		AnsName:                   ansName,
		DisplayName:               req.AgentDisplayName,
		Description:               req.AgentDescription,
		Endpoints:                 eps,
		IdentityCSRPEM:            req.IdentityCSRPEM,
		ServerCsrPEM:              req.ServerCSRPEM,
		ServerCertificatePEM:      req.ServerCertificatePEM,
		ServerCertificateChainPEM: req.ServerCertificateChainPEM,
		// V1 route ⇒ V1 outbox lane. The service stamps
		// `schema_version = "V1"` on the outbox row so the worker
		// POSTs to /v1/internal/agents/event on the TL.
		SchemaVersion: "V1",
	})
	if err != nil {
		h.writeError(w, err)
		return
	}

	WriteJSON(w, http.StatusAccepted, mapV1RegistrationResponse(resp, r))
}

// Detail is the handler for GET /v1/agents/{agentId}. Ownership is
// enforced by `ramiddleware.ReadOwnership` before this runs (404 on
// not-owned); we refetch via the service layer here for testability —
// the handler doesn't depend on middleware wiring in unit tests.
// This mirrors the V2 `LifecycleHandler.Detail` pattern.
func (h *V1RegistrationHandler) Detail(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		h.writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	res, err := h.svc.GetByAgentID(r.Context(), agentID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapV1AgentDetail(res.Registration, res.Endpoints, r, h.svc))
}

// ----- DTO mapping helpers -----

func mapV1EndpointsFromDTO(dtos []v1EndpointDTO) ([]domain.AgentEndpoint, error) {
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

// mapV1RegistrationResponse builds the reference-shaped
// RegistrationPending body. The `nextSteps.endpoint` links point at
// V1 paths (`/v1/agents/{id}/verify-*`) so SDK-generated follow-up
// calls land on the right lane.
func mapV1RegistrationResponse(resp *service.RegisterResponse, r *http.Request) *v1RegistrationPendingResponse {
	dnsRecords := make([]v1DNSRecordDTO, len(resp.DNSRecords))
	for i, rec := range resp.DNSRecords {
		dnsRecords[i] = v1DNSRecordDTO{
			Name:     rec.Name,
			Type:     string(rec.Type),
			Value:    rec.Value,
			Purpose:  string(rec.Purpose),
			Required: rec.Required,
			TTL:      rec.TTL,
		}
	}
	base := schemeOf(r) + "://" + r.Host + "/v1/agents/" + resp.Registration.AgentID

	// Register-time next-steps reflect the deferred-cert flow: certs
	// only issue after verify-acme proves domain control, so the only
	// action the operator can take right now is publish the ACME
	// challenge TXT and call verify-acme. Production DNS records
	// (TRUST/BADGE/DISCOVERY/TLSA) only materialize on the verify-acme
	// 202 response, where they're paired with VERIFY_DNS as the next
	// step. Mirrors the reference's PENDING_VALIDATION handling
	// (RegistrationApiDelegateImpl emits CONFIGURE_DNS + CONFIGURE_HTTP
	// pointing at verify-acme; we omit CONFIGURE_HTTP per the documented
	// DNS-01-only deviation).
	return &v1RegistrationPendingResponse{
		AgentID:    resp.Registration.AgentID,
		Status:     string(resp.Registration.Status),
		AnsName:    resp.Registration.AnsName.String(),
		Challenges: buildV1Challenges(resp.Registration),
		DNSRecords: dnsRecords,
		NextSteps: []v1NextStepDTO{
			{Action: "CONFIGURE_DNS",
				Description: "Publish the ACME DNS-01 challenge TXT record listed in challenges[]",
				Endpoint:    base + "/verify-acme"},
			{Action: "VALIDATE_DOMAIN",
				Description: "Call POST /v1/agents/{agentId}/verify-acme once the challenge record is live",
				Endpoint:    base + "/verify-acme"},
		},
		ExpiresAt: rfc3339Zero(resp.Registration.CertOrder.ExpiresAt),
		Links: []v1LinkDTO{
			{Rel: "self", Href: base},
		},
	}
}

// buildV1Challenges builds the ChallengeInfo array for the V1
// RegistrationPending response. The V1 wire contract carries a single
// DNS_01 entry (the documented V1 deviation — HTTP_01 is V2-only on
// the wire even though the gate accepts either artifact), so only the
// order's DNS-01 challenge is relayed here.
//
// Returns nil (omitted on the wire via the `omitempty` tag) when no
// challenge has been issued — e.g., for an agent past PENDING_DNS or
// a registration pre-dating order persistence.
func buildV1Challenges(reg *domain.AgentRegistration) []v1ChallengeDTO {
	ch, ok := reg.CertOrder.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok {
		return nil
	}
	c := v1ChallengeDTO{
		Type:  "DNS_01",
		Token: ch.Token,
		DNSRecord: &v1ChallengeDNSRecordDTO{
			Name:  ch.EffectiveDNSRecordName(reg.FQDN()),
			Type:  "TXT",
			Value: ch.EffectiveDNSRecordValue(),
		},
		ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
	}
	return []v1ChallengeDTO{c}
}

// rfc3339Zero formats a time.Time as RFC3339 UTC, returning "" for
// zero times so `omitempty` drops the field on the wire. Shared by
// the RegistrationPending + ChallengeInfo expiry fields.
func rfc3339Zero(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// mapV1AgentDetail maps the domain aggregate + its endpoint list to
// the V1 Agent read DTO. Cert-fingerprint info stays out of this
// payload — the reference spec surfaces it via the separate
// `certificates/*` endpoints (that the SDK fetches lazily).
//
// Endpoints arrive as a separate slice because the domain aggregate
// stores them in their own repository; the service layer gathers
// both and hands them in.
func mapV1AgentDetail(reg *domain.AgentRegistration, endpoints []domain.AgentEndpoint, r *http.Request, svc *service.RegistrationService) *v1AgentDetailResponse {
	eps := make([]v1EndpointDTO, len(endpoints))
	for i, e := range endpoints {
		fns := make([]v1FunctionDTO, len(e.Functions))
		for j, f := range e.Functions {
			fns[j] = v1FunctionDTO{ID: f.ID, Name: f.Name, Tags: f.Tags}
		}
		transports := make([]string, len(e.Transports))
		for j, t := range e.Transports {
			transports[j] = string(t)
		}
		eps[i] = v1EndpointDTO{
			AgentURL:         e.AgentURL,
			MetadataURL:      e.MetadataURL,
			MetadataHash:     e.MetadataHash,
			DocumentationURL: e.DocumentationURL,
			Protocol:         string(e.Protocol),
			Functions:        fns,
			Transports:       transports,
		}
	}

	base := schemeOf(r) + "://" + r.Host + "/v1/agents/" + reg.AgentID
	var lastRenewal string
	if !reg.Details.LastRenewalTimestamp.IsZero() {
		lastRenewal = reg.Details.LastRenewalTimestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	// Stamp endpoints onto the aggregate so the buildV1RegistrationPending
	// helper's call to svc.ComputeRequiredDNSRecords produces the
	// full TRUST / BADGE / DISCOVERY / TLSA record set. The service
	// layer returns endpoints as a sibling slice (they live in their
	// own table); the pending block builder needs them on the
	// aggregate to compute the record set correctly.
	reg.Endpoints = endpoints
	return &v1AgentDetailResponse{
		AgentID:               reg.AgentID,
		AnsName:               reg.AnsName.String(),
		AgentDisplayName:      reg.Details.DisplayName,
		AgentDescription:      reg.Details.Description,
		Version:               reg.AnsName.Version().String(),
		AgentHost:             reg.FQDN(),
		AgentStatus:           string(reg.Status),
		Endpoints:             eps,
		RegistrationTimestamp: reg.Details.RegistrationTimestamp.UTC().Format("2006-01-02T15:04:05Z"),
		LastRenewalTimestamp:  lastRenewal,
		RegistrationPending:   buildV1RegistrationPending(reg, r, svc),
		Links: []v1LinkDTO{
			{Rel: "self", Href: base},
		},
	}
}

// buildV1RegistrationPending returns the `registrationPending` block
// surfaced on GET /v1/agents/{id} when the agent has outstanding
// work. Nil when the agent is ACTIVE / REVOKED / DEPRECATED — those
// states are terminal with respect to registration and the response
// omits the block entirely (per the reference capture in
// plan/ANS-public-run).
//
// Status shape per the reference samples:
//
//	PENDING_VALIDATION: challenges (DNS-01 only), CONFIGURE_DNS +
//	                    VALIDATE_DOMAIN nextSteps, expiresAt from
//	                    the ACME challenge deadline.
//	PENDING_DNS:        the production DNS records the agent must
//	                    publish (DISCOVERY/TRUST/BADGE/
//	                    CERTIFICATE_BINDING), VERIFY_DNS nextStep,
//	                    expiresAt scaled from the challenge deadline.
func buildV1RegistrationPending(reg *domain.AgentRegistration, r *http.Request, svc *service.RegistrationService) *v1RegistrationPendingResponse {
	switch reg.Status {
	case domain.StatusPendingValidation:
		base := schemeOf(r) + "://" + r.Host + "/v1/agents/" + reg.AgentID
		if reg.CertOrder.State == domain.OrderStateFailed {
			// Terminal provider failure — relaying the dead challenge
			// with CONFIGURE_DNS would loop the operator into a
			// verify-acme that only returns CERT_ORDER_FAILED.
			return &v1RegistrationPendingResponse{
				Status:  string(reg.Status),
				AnsName: reg.AnsName.String(),
				NextSteps: []v1NextStepDTO{
					{Action: "CANCEL",
						Description: "Certificate issuance failed — cancel this registration (POST /revoke) and register a new version",
						Endpoint:    base + "/revoke"},
				},
				ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
				Links: []v1LinkDTO{
					{Rel: "self", Href: base},
				},
			}
		}
		if reg.CertOrder.State == domain.OrderStateIssuing {
			// Domain control proven; the issuer is still finalizing.
			// The challenge is already answered — relaying it again
			// with CONFIGURE_DNS guidance would mislead the operator.
			return &v1RegistrationPendingResponse{
				Status:  string(reg.Status),
				AnsName: reg.AnsName.String(),
				NextSteps: []v1NextStepDTO{
					{Action: "WAIT",
						Description: "Certificate issuance in progress — POST verify-acme again to check for completion",
						Endpoint:    base + "/verify-acme"},
				},
				ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
				Links: []v1LinkDTO{
					{Rel: "self", Href: base},
				},
			}
		}
		// PENDING_VALIDATION carries no production DNS records — those
		// don't materialize until verify-acme issues the certs that the
		// TLSA record fingerprints. The only record the operator needs
		// at this stage is the ACME challenge TXT, which the
		// `challenges[]` array already exposes in its proper RFC8555
		// representation.
		return &v1RegistrationPendingResponse{
			Status:     string(reg.Status),
			AnsName:    reg.AnsName.String(),
			Challenges: buildV1Challenges(reg),
			DNSRecords: nil,
			NextSteps: []v1NextStepDTO{
				{Action: "CONFIGURE_DNS",
					Description: "Publish the ACME DNS-01 challenge TXT record listed in challenges[]",
					Endpoint:    base + "/verify-acme"},
				{Action: "VALIDATE_DOMAIN",
					Description: "Call POST /v1/agents/{agentId}/verify-acme once the challenge record is live",
					Endpoint:    base + "/verify-acme"},
			},
			ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
			Links: []v1LinkDTO{
				{Rel: "self", Href: base},
			},
		}
	case domain.StatusPendingDNS:
		base := schemeOf(r) + "://" + r.Host + "/v1/agents/" + reg.AgentID
		expected := svc.ComputeRequiredDNSRecords(reg)
		dnsRecords := make([]v1DNSRecordDTO, 0, len(expected))
		for _, rec := range expected {
			dnsRecords = append(dnsRecords, v1DNSRecordDTO{
				Name:     rec.Name,
				Type:     string(rec.Type),
				Value:    rec.Value,
				Purpose:  string(rec.Purpose),
				Required: rec.Required,
				TTL:      rec.TTL,
			})
		}
		return &v1RegistrationPendingResponse{
			Status:     string(reg.Status),
			AnsName:    reg.AnsName.String(),
			DNSRecords: dnsRecords,
			NextSteps: []v1NextStepDTO{
				{Action: "VERIFY_DNS",
					Description: "Verify that all required DNS records are configured",
					Endpoint:    base + "/verify-dns"},
			},
			ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
			Links: []v1LinkDTO{
				{Rel: "self", Href: base},
			},
		}
	default:
		// ACTIVE / REVOKED / DEPRECATED → no pending block.
		return nil
	}
}
