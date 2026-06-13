package handler

import (
	"net/http"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// ----- List DTOs (matches V2 spec AgentListResponse §900) -----

type listResponse struct {
	Items         []listItem `json:"items"`
	ReturnedCount int        `json:"returnedCount"`
	Limit         int        `json:"limit"`
	NextCursor    *string    `json:"nextCursor"`
	HasMore       bool       `json:"hasMore"`
}

type listItem struct {
	AgentID               string        `json:"agentId"`
	AgentDisplayName      string        `json:"agentDisplayName"`
	AgentDescription      string        `json:"agentDescription,omitempty"`
	Version               string        `json:"version"`
	AgentHost             string        `json:"agentHost"`
	AnsName               string        `json:"ansName"`
	Status                string        `json:"status"`
	TTL                   int           `json:"ttl"`
	RegistrationTimestamp string        `json:"registrationTimestamp,omitempty"`
	Endpoints             []endpointDTO `json:"endpoints"`
	Links                 []linkDTO     `json:"links"`
}

func mapListResponse(res *service.ListResult) listResponse {
	items := make([]listItem, 0, len(res.Items))
	for _, reg := range res.Items {
		epSlice := []domain.AgentEndpoint{}
		if eps, ok := res.Endpoints[reg.AgentID]; ok && eps != nil {
			epSlice = eps.Endpoints
		}
		items = append(items, listItem{
			AgentID:               reg.AgentID,
			AgentDisplayName:      reg.Details.DisplayName,
			AgentDescription:      reg.Details.Description,
			Version:               reg.AnsName.Version().String(),
			AgentHost:             reg.AnsName.FQDN(),
			AnsName:               reg.AnsName.String(),
			Status:                string(reg.Status),
			TTL:                   300,
			RegistrationTimestamp: reg.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
			Endpoints:             mapEndpointsToDTO(epSlice),
			Links: []linkDTO{
				{Rel: "self", Href: "/v2/ans/agents/" + reg.AgentID},
			},
		})
	}
	var next *string
	if res.NextCursor != "" {
		v := res.NextCursor
		next = &v
	}
	return listResponse{
		Items:         items,
		ReturnedCount: len(items),
		Limit:         res.Limit,
		NextCursor:    next,
		HasMore:       res.HasMore,
	}
}

// ----- Detail DTO (matches V2 spec AgentDetails §1086) -----

type agentDetails struct {
	AgentID               string                       `json:"agentId"`
	AgentDisplayName      string                       `json:"agentDisplayName"`
	AgentDescription      string                       `json:"agentDescription,omitempty"`
	Version               string                       `json:"version"`
	AgentHost             string                       `json:"agentHost"`
	AnsName               string                       `json:"ansName"`
	AgentStatus           string                       `json:"agentStatus"`
	Endpoints             []endpointDTO                `json:"endpoints"`
	RegistrationTimestamp string                       `json:"registrationTimestamp,omitempty"`
	LastRenewalTimestamp  string                       `json:"lastRenewalTimestamp,omitempty"`
	RegistrationPending   *registrationPendingResponse `json:"registrationPending,omitempty"`
	Links                 []linkDTO                    `json:"links"`
}

func mapAgentDetails(res *service.DetailResult, r *http.Request, tlPublicBaseURL string) agentDetails {
	reg := res.Registration
	// Stamp endpoints onto the aggregate so the pending-block builder's
	// call to domain.ComputeRequiredDNSRecords produces the full record
	// set (endpoints live in their own table and are returned as a
	// sibling slice by the service layer).
	reg.Endpoints = res.Endpoints
	d := agentDetails{
		AgentID:               reg.AgentID,
		AgentDisplayName:      reg.Details.DisplayName,
		AgentDescription:      reg.Details.Description,
		Version:               reg.AnsName.Version().String(),
		AgentHost:             reg.AnsName.FQDN(),
		AnsName:               reg.AnsName.String(),
		AgentStatus:           string(reg.Status),
		Endpoints:             mapEndpointsToDTO(res.Endpoints),
		RegistrationTimestamp: reg.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		RegistrationPending:   buildRegistrationPendingBlock(reg, r, tlPublicBaseURL),
		Links: []linkDTO{
			{Rel: "self", Href: agentURL(r, reg.AgentID)},
		},
	}
	if !reg.Details.LastRenewalTimestamp.IsZero() {
		d.LastRenewalTimestamp = reg.Details.LastRenewalTimestamp.Format("2006-01-02T15:04:05Z07:00")
	}
	return d
}

// buildRegistrationPendingBlock is the V2 equivalent of
// buildV1RegistrationPending. Agents still driving validation/DNS
// expose the outstanding challenges + DNS records needed to
// progress; terminal states omit the block.
//
// The block's status is a registration-flow status, NOT the agent
// lifecycle status: while an asynchronous issuer finalizes the
// certificate order the lifecycle stays PENDING_VALIDATION but the
// flow reports PENDING_CERTS (per the spec's RegistrationPending
// enum), with WAIT guidance pointing back at verify-acme.
func buildRegistrationPendingBlock(reg *domain.AgentRegistration, r *http.Request, tlPublicBaseURL string) *registrationPendingResponse {
	switch reg.Status {
	case domain.StatusPendingValidation:
		base := schemeOf(r) + "://" + r.Host + "/v2/ans/agents/" + reg.AgentID
		if reg.CertOrder.State == domain.OrderStateFailed {
			// Terminal provider failure. The dead challenges are not
			// worth relaying, and CONFIGURE_DNS/VALIDATE_DOMAIN would
			// loop the operator into a verify-acme that only returns
			// CERT_ORDER_FAILED. The actionable step is to cancel and
			// register a new version (the ANS name is immutable once
			// used).
			return &registrationPendingResponse{
				AgentID: reg.AgentID,
				Status:  registrationStatusPendingCerts,
				AnsName: reg.AnsName.String(),
				NextSteps: []nextStepDTO{
					{Action: "CANCEL",
						Description: "Certificate issuance failed — cancel this registration (POST /revoke) and register a new version",
						Endpoint:    base + "/revoke"},
				},
				ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
				Links: []linkDTO{
					{Rel: "self", Href: base},
				},
			}
		}
		if reg.CertOrder.State == domain.OrderStateIssuing {
			// Domain control proven; the issuer is still finalizing.
			// No challenges (already answered), no production DNS
			// records (the TLSA value needs the cert).
			return &registrationPendingResponse{
				AgentID: reg.AgentID,
				Status:  registrationStatusPendingCerts,
				AnsName: reg.AnsName.String(),
				NextSteps: []nextStepDTO{
					{Action: "WAIT",
						Description: "Certificate issuance in progress — POST verify-acme again to check for completion",
						Endpoint:    base + "/verify-acme"},
				},
				ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
				Links: []linkDTO{
					{Rel: "self", Href: base},
				},
			}
		}
		// PENDING_VALIDATION carries no production DNS records — those
		// only materialize after verify-acme issues the certs that the
		// TLSA record fingerprints. The ACME challenge itself rides in
		// challenges[] in its RFC8555 representation; surfacing it
		// again here as a generic dnsRecord would imply the operator
		// should publish production records too, which they can't
		// without certs in hand.
		return &registrationPendingResponse{
			AgentID:    reg.AgentID,
			Status:     string(reg.Status),
			AnsName:    reg.AnsName.String(),
			Challenges: buildRegistrationChallenges(reg),
			DNSRecords: nil,
			NextSteps: []nextStepDTO{
				{Action: "CONFIGURE_DNS",
					Description: "Publish one challenge artifact from challenges[]: the DNS-01 TXT record, or the HTTP-01 resource at its httpPath",
					Endpoint:    base + "/verify-acme"},
				{Action: "VALIDATE_DOMAIN",
					Description: "Call POST /v2/ans/agents/{agentId}/verify-acme once the challenge artifact is live",
					Endpoint:    base + "/verify-acme"},
			},
			ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
			Links: []linkDTO{
				{Rel: "self", Href: base},
			},
		}
	case domain.StatusPendingDNS:
		base := schemeOf(r) + "://" + r.Host + "/v2/ans/agents/" + reg.AgentID
		expected := domain.ComputeRequiredDNSRecords(reg, tlPublicBaseURL)
		dnsRecords := make([]dnsRecordDTO, 0, len(expected))
		for _, rec := range expected {
			dnsRecords = append(dnsRecords, dnsRecordDTO{
				Name:     rec.Name,
				Type:     string(rec.Type),
				Value:    rec.Value,
				Purpose:  string(rec.Purpose),
				Required: rec.Required,
				TTL:      rec.TTL,
			})
		}
		return &registrationPendingResponse{
			AgentID:    reg.AgentID,
			Status:     string(reg.Status),
			AnsName:    reg.AnsName.String(),
			DNSRecords: dnsRecords,
			NextSteps: []nextStepDTO{
				{Action: "VERIFY_DNS",
					Description: "Verify that all required DNS records are configured",
					Endpoint:    base + "/verify-dns"},
			},
			ExpiresAt: rfc3339Zero(reg.CertOrder.ExpiresAt),
			Links: []linkDTO{
				{Rel: "self", Href: base},
			},
		}
	default:
		return nil
	}
}

// registrationStatusPendingCerts is the registration-flow status
// reported while a certificate order is finalizing. It exists only in
// the RegistrationPending view (spec `RegistrationPending.status`
// enum) — the agent lifecycle enum deliberately does not contain it.
const registrationStatusPendingCerts = "PENDING_CERTS"

// ----- Certificate DTO (matches V2 spec CertificateResponse §1324) -----

type certificateResponse struct {
	CsrID                         string `json:"csrId,omitempty"`
	CertificateSubject            string `json:"certificateSubject,omitempty"`
	CertificateIssuer             string `json:"certificateIssuer,omitempty"`
	CertificateSerialNumber       string `json:"certificateSerialNumber,omitempty"`
	CertificateValidFrom          string `json:"certificateValidFrom"`
	CertificateValidTo            string `json:"certificateValidTo"`
	CertificatePEM                string `json:"certificatePEM"`
	ChainPEM                      string `json:"chainPEM,omitempty"`
	CertificatePublicKeyAlgorithm string `json:"certificatePublicKeyAlgorithm,omitempty"`
	CertificateSignatureAlgorithm string `json:"certificateSignatureAlgorithm,omitempty"`
}

func mapCertificate(c *domain.StoredCertificate) certificateResponse {
	resp := certificateResponse{
		CsrID:                c.CSRID,
		CertificatePEM:       c.CertificatePEM,
		ChainPEM:             c.ChainPEM,
		CertificateValidFrom: c.IssueTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		CertificateValidTo:   c.ExpirationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
	// Parse the leaf to fill subject/issuer/serial/algorithms. On
	// parse failure we leave those fields empty (reference logs a
	// warning and drops the cert entirely; we're more permissive —
	// the caller still gets the PEM and can parse it themselves).
	// This matches the "best-effort extraction" intent of the
	// reference RA's `certificateParser.extractCertificateInfo`.
	if info, ok := extractCertInfo(c.CertificatePEM); ok {
		resp.CertificateSubject = info.Subject
		resp.CertificateIssuer = info.Issuer
		resp.CertificateSerialNumber = info.SerialNumber
		resp.CertificatePublicKeyAlgorithm = info.PublicKeyAlgorithm
		resp.CertificateSignatureAlgorithm = info.SignatureAlgorithm
	}
	return resp
}

// extractCertInfo parses a PEM-encoded certificate and returns its
// metadata. Returns ok=false on any parse error — the caller uses a
// zero-value info struct in that case.
func extractCertInfo(pemStr string) (certInfo, bool) {
	if pemStr == "" {
		return certInfo{}, false
	}
	// Imports live at the top of this file; the parser itself is in
	// the certificate-helpers file to keep this DTO file focused.
	return parseCertPEM(pemStr)
}

type certInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	PublicKeyAlgorithm string
	SignatureAlgorithm string
}

// ----- CSR submission / status (matches V2 spec §1362-1407) -----

// csrSubmissionRequest is the POST body for both
// /certificates/identity and /certificates/server. Mirrors V2
// `CsrSubmissionRequest` (§1362).
type csrSubmissionRequest struct {
	CsrPEM string `json:"csrPEM"`
}

// csrSubmissionResponse mirrors V2 `CsrSubmissionResponse` (§1370).
type csrSubmissionResponse struct {
	CsrID   string `json:"csrId"`
	Message string `json:"message,omitempty"`
}

// csrStatusResponse mirrors V2 `CsrStatusResponse` (§1381).
// failureReason is a pointer so we can omit it cleanly when nil —
// the reference also marks it nullable.
type csrStatusResponse struct {
	CsrID         string  `json:"csrId"`
	Type          string  `json:"type"`
	Status        string  `json:"status"`
	SubmittedAt   string  `json:"submittedAt"`
	UpdatedAt     string  `json:"updatedAt"`
	FailureReason *string `json:"failureReason,omitempty"`
}

// ----- Server certificate renewal DTOs (V2 §1409-1513) -----

// serverCertRenewalRequest mirrors V2 `ServerCertificateRenewalRequest`
// §1409. Exactly one of ServerCsrPEM / ServerCertificatePEM must be
// set; both or neither are 422.
type serverCertRenewalRequest struct {
	ServerCsrPEM              string `json:"serverCsrPEM,omitempty"`
	ServerCertificatePEM      string `json:"serverCertificatePEM,omitempty"`
	ServerCertificateChainPEM string `json:"serverCertificateChainPEM,omitempty"`
}

// challengeInfo mirrors the V2 `ChallengeInfo` schema — the same
// shape the registration lane's challenges[] carries: type, token,
// keyAuthorization, dnsRecord, httpPath, expiresAt. The renewal
// responses reference ChallengeInfo via $ref, so the field names
// must match it exactly. We omit-empty so DNS-01 entries don't carry
// an httpPath and vice versa.
type challengeInfo struct {
	Type             string                 `json:"type"`
	Token            string                 `json:"token"`
	KeyAuthorization string                 `json:"keyAuthorization,omitempty"`
	DNSRecord        *challengeDNSRecordDTO `json:"dnsRecord,omitempty"`
	HTTPPath         string                 `json:"httpPath,omitempty"`
	ExpiresAt        string                 `json:"expiresAt"`
}

type renewalChallenges struct {
	DNS01  *challengeInfo `json:"dns01,omitempty"`
	HTTP01 *challengeInfo `json:"http01,omitempty"`
}

// nextStep mirrors V2 `NextStep` — guidance the caller follows to
// progress the renewal state machine.
type nextStep struct {
	Action      string `json:"action"`
	Endpoint    string `json:"endpoint,omitempty"`
	Description string `json:"description,omitempty"`
}

type linkRef struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// renewalSubmissionResponse mirrors V2 `RenewalSubmissionResponse` §1422.
type renewalSubmissionResponse struct {
	RenewalType string             `json:"renewalType"`
	Status      string             `json:"status"`
	CsrID       string             `json:"csrId,omitempty"`
	Challenges  *renewalChallenges `json:"challenges,omitempty"`
	ExpiresAt   string             `json:"expiresAt"`
	NextStep    nextStep           `json:"nextStep"`
	Links       []linkRef          `json:"links,omitempty"`
}

// renewalStatusResponse mirrors V2 `RenewalStatusResponse` §1458.
type renewalStatusResponse struct {
	RenewalType   string             `json:"renewalType"`
	Status        string             `json:"status"`
	CsrID         string             `json:"csrId,omitempty"`
	Challenges    *renewalChallenges `json:"challenges,omitempty"`
	TlsaDNSRecord *dnsRecordDTO      `json:"tlsaDnsRecord,omitempty"`
	FailureReason string             `json:"failureReason,omitempty"`
	ExpiresAt     string             `json:"expiresAt"`
	NextStep      nextStep           `json:"nextStep"`
}

// renewalVerificationResponse mirrors V2 `RenewalVerificationResponse` §1496.
type renewalVerificationResponse struct {
	Status        string        `json:"status"`
	CsrID         string        `json:"csrId,omitempty"`
	TlsaDNSRecord *dnsRecordDTO `json:"tlsaDnsRecord,omitempty"`
	NextStep      nextStep      `json:"nextStep"`
}

// mapCSRStatus converts a domain.AgentCSR into the wire-format
// `CsrStatusResponse`. When the CSR is in state REJECTED and has no
// explicit rejectionReason, we synthesize a placeholder the way the
// reference RA's `computeFailureReason` does: a generic message
// keeps clients from seeing `null` + undefined UX.
func mapCSRStatus(c *domain.AgentCSR) csrStatusResponse {
	submitted := c.SubmissionTimestamp.Format("2006-01-02T15:04:05Z07:00")
	updated := submitted
	if !c.ProcessedTimestamp.IsZero() {
		updated = c.ProcessedTimestamp.Format("2006-01-02T15:04:05Z07:00")
	}
	resp := csrStatusResponse{
		CsrID:       c.CSRID,
		Type:        string(c.Type),
		Status:      string(c.Status),
		SubmittedAt: submitted,
		UpdatedAt:   updated,
	}
	if c.Status == domain.CSRStatusRejected {
		reason := c.RejectionReason
		if reason == "" {
			reason = "Certificate issuance failed. Please retry with a new CSR."
		}
		resp.FailureReason = &reason
	}
	return resp
}

// ----- AgentStatus (matches V2 spec §1133) -----

type agentStatus struct {
	Status         string   `json:"status"`
	Phase          string   `json:"phase,omitempty"`
	CompletedSteps []string `json:"completedSteps,omitempty"`
	PendingSteps   []string `json:"pendingSteps,omitempty"`
	CreatedAt      string   `json:"createdAt,omitempty"`
	UpdatedAt      string   `json:"updatedAt,omitempty"`
	ExpiresAt      string   `json:"expiresAt,omitempty"`
}

// phaseFor derives the V2 AgentStatus phase from (lifecycle status ×
// certificate-order state). Reference semantics: PENDING_VALIDATION →
// DOMAIN_VALIDATION, PENDING_DNS → DNS_PROVISIONING, ACTIVE →
// COMPLETED — plus CERTIFICATE_ISSUANCE, which is not a lifecycle
// state at all: it is the window where domain validation passed but
// an asynchronous issuer hasn't produced the certificate yet, tracked
// on the order while the lifecycle stays PENDING_VALIDATION.
func phaseFor(reg *domain.AgentRegistration) string {
	switch reg.Status {
	case domain.StatusPendingValidation:
		if reg.CertOrder.State == domain.OrderStateIssuing {
			return "CERTIFICATE_ISSUANCE"
		}
		return "DOMAIN_VALIDATION"
	case domain.StatusPendingDNS:
		return "DNS_PROVISIONING"
	case domain.StatusActive:
		return renewalStatusCompleted
	default:
		return "INITIALIZATION"
	}
}

func completedStepsFor(reg *domain.AgentRegistration) []string {
	switch {
	case reg.Status == domain.StatusPendingValidation && reg.CertOrder.State == domain.OrderStateIssuing:
		return []string{"DOMAIN_VALIDATION"}
	case reg.Status == domain.StatusPendingDNS:
		// The cert exists by PENDING_DNS — issuance completes in the
		// same transaction that advances the lifecycle.
		return []string{"DOMAIN_VALIDATION", "CERTIFICATE_ISSUANCE"}
	case reg.Status == domain.StatusActive:
		return []string{"DOMAIN_VALIDATION", "CERTIFICATE_ISSUANCE", "DNS_PROVISIONING"}
	default:
		return nil
	}
}

func pendingStepsFor(reg *domain.AgentRegistration) []string {
	switch {
	case reg.Status == domain.StatusPendingValidation && reg.CertOrder.State == domain.OrderStateIssuing:
		return []string{"CERTIFICATE_ISSUANCE"}
	case reg.Status == domain.StatusPendingValidation:
		return []string{"DOMAIN_VALIDATION"}
	case reg.Status == domain.StatusPendingDNS:
		return []string{"DNS_PROVISIONING"}
	default:
		return nil
	}
}

// ----- Revocation DTOs (matches V2 spec §1044-1084) -----

type revocationRequest struct {
	Reason   string `json:"reason"`
	Comments string `json:"comments,omitempty"`
}

type revocationResponse struct {
	AgentID            string         `json:"agentId"`
	AnsName            string         `json:"ansName"`
	Status             string         `json:"status"`
	RevokedAt          string         `json:"revokedAt"`
	Reason             string         `json:"reason"`
	DNSRecordsToRemove []dnsRecordDTO `json:"dnsRecordsToRemove,omitempty"`
	Links              []linkDTO      `json:"links"`
}

// ----- DnsVerificationError (matches V2 spec §1533-1552) -----

type dnsVerificationError struct {
	Status           string               `json:"status"`
	MissingRecords   []dnsRecordDTO       `json:"missingRecords,omitempty"`
	IncorrectRecords []incorrectRecordDTO `json:"incorrectRecords,omitempty"`
}

type incorrectRecordDTO struct {
	Record   dnsRecordDTO `json:"record"`
	Found    string       `json:"found"`
	Expected string       `json:"expected"`
}

func dnsMissingFrom(mismatches []service.DNSMismatch) []dnsRecordDTO {
	var out []dnsRecordDTO
	for _, m := range mismatches {
		if m.Code != "MISSING" {
			continue
		}
		out = append(out, dnsRecordDTO{
			Name:     m.Expected.Name,
			Type:     string(m.Expected.Type),
			Value:    m.Expected.Value,
			Purpose:  string(m.Expected.Purpose),
			Required: m.Expected.Required,
			TTL:      m.Expected.TTL,
		})
	}
	return out
}

func dnsIncorrectFrom(mismatches []service.DNSMismatch) []incorrectRecordDTO {
	var out []incorrectRecordDTO
	for _, m := range mismatches {
		// MISMATCH = required record with wrong value.
		// TLSA_DNSSEC_MISMATCH = TLSA response came back
		// DNSSEC-authenticated but didn't match the expected cert
		// fingerprint (signed-zone tampering). Both surface as
		// incorrect records — same DTO shape.
		if m.Code != "MISMATCH" && m.Code != "TLSA_DNSSEC_MISMATCH" {
			continue
		}
		out = append(out, incorrectRecordDTO{
			Record: dnsRecordDTO{
				Name:     m.Expected.Name,
				Type:     string(m.Expected.Type),
				Value:    m.Expected.Value,
				Purpose:  string(m.Expected.Purpose),
				Required: m.Expected.Required,
				TTL:      m.Expected.TTL,
			},
			Found:    m.Found,
			Expected: m.Expected.Value,
		})
	}
	return out
}

// ----- shared helpers -----

func mapEndpointsToDTO(eps []domain.AgentEndpoint) []endpointDTO {
	out := make([]endpointDTO, 0, len(eps))
	for _, ep := range eps {
		funcs := make([]functionDTO, 0, len(ep.Functions))
		for _, f := range ep.Functions {
			funcs = append(funcs, functionDTO{ID: f.ID, Name: f.Name, Tags: f.Tags})
		}
		transports := make([]string, 0, len(ep.Transports))
		for _, t := range ep.Transports {
			transports = append(transports, string(t))
		}
		out = append(out, endpointDTO{
			AgentURL:         ep.AgentURL,
			MetadataURL:      ep.MetadataURL,
			MetadataHash:     ep.MetadataHash,
			DocumentationURL: ep.DocumentationURL,
			Protocol:         string(ep.Protocol),
			Functions:        funcs,
			Transports:       transports,
		})
	}
	return out
}

// identityFromRequest unwraps the authenticated Identity. Exported
// only to the handler package; callers who already hold the request
// use this rather than reaching into the auth package directly.
func identityFromRequest(r *http.Request) (*port.Identity, bool) {
	return auth.IdentityFromContext(r.Context())
}

// agentURL builds the canonical self-link for an agent.
func agentURL(r *http.Request, agentID string) string {
	return schemeOf(r) + "://" + r.Host + "/v2/ans/agents/" + agentID
}
