package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// V1 registration handler tests. The fixture in lifecycle_test.go
// mounts both V1 and V2 routes on the same router so we can drive
// them through the same machinery.

// v1RegisterAgent is the V1 analogue of handlerFixture.registerAgent.
// Returns the new agentId + the raw 202 response body for tests that
// want to assert on the RegistrationPending shape.
//
// Uses the CSR path (both identityCsrPEM + serverCsrPEM), matching
// the reference's default registration expectation.
func (f *handlerFixture) v1RegisterAgent(t *testing.T, ownerID, host, version string) (agentID string, body []byte) {
	t.Helper()
	identityCSR := newTestCSR(t, "ans://v"+version+"."+host)
	serverCSR := newTestServerCSR(t, host)
	reqBody, _ := json.Marshal(map[string]any{
		"agentDisplayName": "V1 Test Agent",
		"agentDescription": "ans V1 SDK smoke test",
		"version":          version,
		"agentHost":        host,
		"endpoints": []map[string]any{
			{
				"agentUrl":   "https://" + host + "/mcp",
				"protocol":   "MCP",
				"transports": []string{"SSE"},
			},
		},
		"identityCsrPEM": identityCSR,
		"serverCsrPEM":   serverCSR,
	})
	rec := f.request(t, http.MethodPost, "/v1/agents/register", bytes.NewReader(reqBody), f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("V1 register %s: status=%d body=%s", host, rec.Code, rec.Body)
	}
	var parsed struct {
		AgentID string `json:"agentId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("parse V1 register response: %v", err)
	}
	return parsed.AgentID, rec.Body.Bytes()
}

// TestV1Register_HappyPath exercises the full V1 registration shape.
// The fields, enum values, and link targets must match the reference
// `RegistrationPending` schema byte-for-byte — SDK clients generated
// from the reference swagger decode based on exact tags.
func TestV1Register_HappyPath(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)

	agentID, body := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	if agentID == "" {
		t.Fatal("agentId empty on 202")
	}

	// Reference-parity spot checks on top-level fields.
	var resp struct {
		AgentID    string `json:"agentId"`
		Status     string `json:"status"`
		AnsName    string `json:"ansName"`
		DNSRecords []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Required bool   `json:"required"`
		} `json:"dnsRecords"`
		Challenges []struct {
			Type string `json:"type"`
		} `json:"challenges"`
		NextSteps []struct {
			Action   string `json:"action"`
			Endpoint string `json:"endpoint,omitempty"`
		} `json:"nextSteps"`
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.AgentID, agentID)
	}
	if resp.Status != "PENDING_VALIDATION" {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
	if resp.AnsName != "ans://v1.0.0.agent.example.com" {
		t.Errorf("ansName: got %q", resp.AnsName)
	}
	// Register-time 202 intentionally has NO `dnsRecords[]` —
	// production DNS records (TRUST/BADGE/DISCOVERY/TLSA) only
	// materialize after verify-acme issues the certs. The
	// operator's DNS action at this stage is the ACME challenge,
	// surfaced in `challenges[]`.
	if len(resp.DNSRecords) != 0 {
		t.Errorf("dnsRecords should be empty before verify-acme, got %d entries", len(resp.DNSRecords))
	}
	if len(resp.Challenges) == 0 {
		t.Error("challenges[] should carry the ACME DNS-01 challenge at register time")
	}

	// Every nextSteps.endpoint MUST target `/v1/…` — if the V1
	// handler leaks V2 URLs the SDK's follow-up calls hit the wrong
	// lane.
	for _, step := range resp.NextSteps {
		if step.Endpoint == "" {
			continue
		}
		if !strings.Contains(step.Endpoint, "/v1/agents/") {
			t.Errorf("nextStep[%s]: endpoint must be on /v1/, got %q", step.Action, step.Endpoint)
		}
	}
	if len(resp.Links) == 0 {
		t.Error("self link missing")
	}
	if !strings.Contains(resp.Links[0].Href, "/v1/agents/"+agentID) {
		t.Errorf("self link: got %q (must point to V1 path)", resp.Links[0].Href)
	}
}

// TestV1Register_AcceptsBothPaths pins the reference-parity shape:
// V1 registration accepts either `serverCsrPEM` (→ RA signs via the
// configured server CA) or `serverCertificatePEM` (BYOC). Both must
// produce a 202 + an issued/validated server cert that the GET
// endpoint surfaces.
func TestV1Register_AcceptsBothPaths(t *testing.T) {
	t.Parallel()

	t.Run("CSR path", func(t *testing.T) {
		t.Parallel()
		fx := newHandlerFixture(t)
		// v1RegisterAgent uses the CSR path; cert issuance happens at
		// verify-acme, not at register. Drive the lifecycle forward
		// before asserting the server cert landed in the store.
		agentID, _ := fx.v1RegisterAgent(t, "alice", "csr.example.com", "1.0.0")
		if rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
			t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
		}
		rec := fx.request(t, http.MethodGet, "/v1/agents/"+agentID+"/certificates/server", nil, fx.asOwner("alice"))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET server certs: %d %s", rec.Code, rec.Body)
		}
		var certs []any
		_ = json.Unmarshal(rec.Body.Bytes(), &certs)
		if len(certs) != 1 {
			t.Errorf("CSR path must produce 1 server cert, got %d", len(certs))
		}
	})

	t.Run("BYOC path", func(t *testing.T) {
		t.Parallel()
		fx := newHandlerFixture(t)
		host := "byoc.example.com"
		leafPEM, chainPEM := selfSignedLeafAndChain(t, host)
		identityCSR := newTestCSR(t, "ans://v1.0.0."+host)
		reqBody, _ := json.Marshal(map[string]any{
			"agentDisplayName": "BYOC",
			"version":          "1.0.0",
			"agentHost":        host,
			"endpoints": []map[string]any{
				{"agentUrl": "https://" + host + "/mcp", "protocol": "MCP"},
			},
			"identityCsrPEM":            identityCSR,
			"serverCertificatePEM":      leafPEM,
			"serverCertificateChainPEM": chainPEM,
		})
		rec := fx.request(t, http.MethodPost, "/v1/agents/register",
			bytes.NewReader(reqBody), fx.asOwner("alice"))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("BYOC register: %d %s", rec.Code, rec.Body)
		}
	})
}

// TestV1Register_BothOrNeither_422 confirms the at-most-one constraint
// on server-cert input matches the reference spec: caller must set
// exactly ONE of serverCsrPEM / serverCertificatePEM.
func TestV1Register_BothOrNeither_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "both.example.com"
	identityCSR := newTestCSR(t, "ans://v1.0.0."+host)

	// Neither set.
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        host,
		"endpoints": []map[string]any{
			{"agentUrl": "https://" + host + "/mcp", "protocol": "MCP"},
		},
		"identityCsrPEM": identityCSR,
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("neither: got %d want 422", rec.Code)
	}

	// Both set.
	body, _ = json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        host,
		"endpoints": []map[string]any{
			{"agentUrl": "https://" + host + "/mcp", "protocol": "MCP"},
		},
		"identityCsrPEM":       identityCSR,
		"serverCsrPEM":         newTestServerCSR(t, host),
		"serverCertificatePEM": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
	})
	rec = fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("both: got %d want 422", rec.Code)
	}
}

// TestV1Register_MissingIdentityCSR_422 confirms the handler rejects
// requests without `identityCsrPEM` (required field per the
// reference V1 API spec).
func TestV1Register_MissingIdentityCSR_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	reqBody, _ := json.Marshal(map[string]any{
		"agentDisplayName": "No CSR",
		"version":          "1.0.0",
		"agentHost":        "agent.example.com",
		"endpoints": []map[string]any{
			{"agentUrl": "https://agent.example.com/mcp", "protocol": "MCP"},
		},
		// identityCsrPEM intentionally omitted.
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(reqBody), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestV1Detail_OwnedReturns200 reads back a V1 registration through
// the V1 detail route. Shape assertions pin reference-parity fields
// — field names match the reference RA's `Agent` schema byte-for-byte.
func TestV1Detail_OwnedReturns200(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v1/agents/"+agentID, nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentID               string `json:"agentId"`
		AnsName               string `json:"ansName"`
		AgentDisplayName      string `json:"agentDisplayName"`
		AgentStatus           string `json:"agentStatus"`
		AgentHost             string `json:"agentHost"`
		Version               string `json:"version"`
		RegistrationTimestamp string `json:"registrationTimestamp"`
		Endpoints             []struct {
			Protocol string `json:"protocol"`
			AgentURL string `json:"agentUrl"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.AgentID, agentID)
	}
	if resp.AgentStatus != "PENDING_VALIDATION" {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.AgentStatus)
	}
	if resp.AgentHost != "agent.example.com" {
		t.Errorf("agentHost: got %q", resp.AgentHost)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("version: got %q", resp.Version)
	}
	if resp.RegistrationTimestamp == "" {
		t.Error("registrationTimestamp missing")
	}
	if len(resp.Endpoints) != 1 || resp.Endpoints[0].Protocol != "MCP" {
		t.Errorf("endpoints mismatch: %+v", resp.Endpoints)
	}
}

// TestV1Register_NoTLEmitAtRegistration pins the V1-parity rule:
// the V1 enum has only terminal states, so POST /v1/agents/register
// does NOT write a TL leaf — the first V1 leaf appears on
// verify-dns success (AGENT_REGISTERED). A previous implementation
// erroneously emitted AGENT_REGISTERED here, producing two
// identical terminal leaves per agent (once at register, once at
// verify-dns). This test guards against that regression.
//
// The V2 counterpart (register → AGENT_REGISTRATION intermediate) is
// separately covered by TestV2Register_StampsV2SchemaOnOutbox.
func TestV1Register_NoTLEmitAtRegistration(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatalf("claim outbox: %v", err)
	}
	for _, row := range rows {
		if row.AgentID == agentID {
			t.Errorf("V1 register must not emit a TL leaf; found row event_type=%q schema_version=%q",
				row.EventType, row.SchemaVersion)
		}
	}
}

// TestV2Register_StampsV2SchemaOnOutbox is the counterpart: POSTing
// to /v2/ans/agents must keep stamping `schema_version = "V2"` on
// the outbox. Pairs with the V1 test above so the dual-lane contract
// is enforced end-to-end.
func TestV2Register_StampsV2SchemaOnOutbox(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "v2agent.example.com", "1.0.0")

	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatalf("claim outbox: %v", err)
	}
	for _, row := range rows {
		if row.AgentID != agentID {
			continue
		}
		if row.SchemaVersion != "V2" {
			t.Errorf("V2 register stamped schema_version=%q, want V2", row.SchemaVersion)
		}
		if row.EventType != "AGENT_REGISTRATION" {
			t.Errorf("V2 register event_type=%q, want AGENT_REGISTRATION", row.EventType)
		}
	}
}

// TestV1Detail_NotOwnedReturns404 confirms the V1 detail route
// inherits the V2 hide-existence behavior — a caller who doesn't
// own the agent gets a 404, not a 403. Prevents enumeration.
func TestV1Detail_NotOwnedReturns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v1/agents/"+agentID, nil, fx.asOwner("bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}
