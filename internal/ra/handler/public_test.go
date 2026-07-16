package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/godaddy/ans/internal/ra/handler"
)

// Public-endpoint integration tests. Reuses the same handlerFixture as
// the lifecycle tests; the difference is the /v2/public/agents routes
// are exercised WITHOUT injecting an identity (no asOwner tweak).

func TestPublicList_ReturnsActiveAgents(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	agentID := fx.registerAgent(t, "alice", "pub.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Items []struct {
			AgentID  string `json:"agentId"`
			AnsName  string `json:"ansName"`
			AgentHost string `json:"agentHost"`
		} `json:"items"`
		ReturnedCount int  `json:"returnedCount"`
		HasMore       bool `json:"hasMore"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ReturnedCount != 1 {
		t.Fatalf("want 1 item, got %d", resp.ReturnedCount)
	}
	if resp.Items[0].AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.Items[0].AgentID, agentID)
	}
}

func TestPublicList_CrossOwnerVisibility(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	a1 := fx.registerAgent(t, "alice", "alice.example.com", "1.0.0")
	fx.activateAgent(t, "alice", a1)
	a2 := fx.registerAgent(t, "bob", "bob.example.com", "1.0.0")
	fx.activateAgent(t, "bob", a2)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Items []struct {
			AgentID string `json:"agentId"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 2 {
		t.Fatalf("public list should see both owners' agents; got %d", len(resp.Items))
	}
	seen := map[string]bool{}
	for _, it := range resp.Items {
		seen[it.AgentID] = true
	}
	if !seen[a1] || !seen[a2] {
		t.Errorf("missing agent(s): %v", seen)
	}
}

func TestPublicList_DefaultStatusACTIVE(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	// Register without activating → PENDING_VALIDATION.
	fx.registerAgent(t, "alice", "pending.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/public/agents", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Items []any `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 0 {
		t.Errorf("default ACTIVE filter should hide pending agents; got %d items", len(resp.Items))
	}
}

func TestPublicList_InvalidLimit(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents?limit=999", nil, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", rec.Code)
	}
}

func TestPublicList_StatusFilterALL(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	a1 := fx.registerAgent(t, "alice", "all1.example.com", "1.0.0")
	fx.activateAgent(t, "alice", a1)
	// a2 stays in PENDING_VALIDATION.
	fx.registerAgent(t, "alice", "all2.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/public/agents?status=ALL", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		ReturnedCount int `json:"returnedCount"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ReturnedCount != 2 {
		t.Errorf("status=ALL should return both agents; got %d", resp.ReturnedCount)
	}
}

func TestPublicList_ExplicitStatusFilter(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	a1 := fx.registerAgent(t, "alice", "exp1.example.com", "1.0.0")
	fx.activateAgent(t, "alice", a1)
	// a2 stays in PENDING_VALIDATION.
	fx.registerAgent(t, "alice", "exp2.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/public/agents?status=PENDING_VALIDATION", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		ReturnedCount int `json:"returnedCount"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ReturnedCount != 1 {
		t.Errorf("status=PENDING_VALIDATION should return 1; got %d", resp.ReturnedCount)
	}
}

func TestPublicList_ValidLimit(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	for i := range 3 {
		id := fx.registerAgent(t, "alice", fmt.Sprintf("lim%d.example.com", i), "1.0.0")
		fx.activateAgent(t, "alice", id)
	}

	rec := fx.request(t, http.MethodGet, "/v2/public/agents?limit=2", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		ReturnedCount int  `json:"returnedCount"`
		Limit         int  `json:"limit"`
		HasMore       bool `json:"hasMore"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ReturnedCount != 2 {
		t.Errorf("want 2 items, got %d", resp.ReturnedCount)
	}
	if resp.Limit != 2 {
		t.Errorf("limit: got %d want 2", resp.Limit)
	}
	if !resp.HasMore {
		t.Error("hasMore should be true with 3 agents and limit=2")
	}
}

func TestPublicList_HostFilter(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	a1 := fx.registerAgent(t, "alice", "alpha.example.com", "1.0.0")
	fx.activateAgent(t, "alice", a1)
	a2 := fx.registerAgent(t, "bob", "beta.example.com", "1.0.0")
	fx.activateAgent(t, "bob", a2)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents?agentHost=alpha.example.com", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Items []struct {
			AgentHost string `json:"agentHost"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 1 {
		t.Fatalf("want 1 filtered result, got %d", len(resp.Items))
	}
	if resp.Items[0].AgentHost != "alpha.example.com" {
		t.Errorf("host: got %q", resp.Items[0].AgentHost)
	}
}

func TestPublicList_SelfLinkPrefix(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	agentID := fx.registerAgent(t, "alice", "link.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Items []struct {
			Links []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"links"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 1 || len(resp.Items[0].Links) == 0 {
		t.Fatalf("expected one item with links; got %d items", len(resp.Items))
	}
	want := "/v2/public/agents/" + agentID
	got := resp.Items[0].Links[0].Href
	if got != want {
		t.Errorf("self link: got %q want %q", got, want)
	}
}

func TestPublicDetail_ReturnsAgent(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	agentID := fx.registerAgent(t, "alice", "detail.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents/"+agentID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentID     string `json:"agentId"`
		AgentStatus string `json:"agentStatus"`
		AnsName     string `json:"ansName"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.AgentID, agentID)
	}
	if resp.AgentStatus != "ACTIVE" {
		t.Errorf("status: got %q want ACTIVE", resp.AgentStatus)
	}
}

func TestPublicDetail_NoPendingBlock(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	// Leave agent in PENDING_VALIDATION — it has a non-nil
	// registrationPending block internally. The public endpoint
	// must strip it.
	agentID := fx.registerAgent(t, "alice", "pend.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/public/agents/"+agentID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if rp, ok := raw["registrationPending"]; ok && rp != nil {
		t.Errorf("registrationPending must be null/absent on public detail; got %v", rp)
	}
}

func TestPublicDetail_SelfLinkPrefix(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	agentID := fx.registerAgent(t, "alice", "selflink.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/public/agents/"+agentID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	want := "/v2/public/agents/" + agentID
	found := false
	for _, l := range resp.Links {
		if l.Rel == "self" && l.Href == want {
			found = true
		}
	}
	if !found {
		t.Errorf("self link not found or wrong; got %+v", resp.Links)
	}
}

func TestPublicDetail_NotFound(t *testing.T) {
	t.Parallel()
	fx := newPublicFixture(t)

	rec := fx.request(t, http.MethodGet, "/v2/public/agents/00000000-0000-0000-0000-000000000000", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// ----- fixture -----

// newPublicFixture reuses the handler fixture but also mounts the
// public discovery routes. Authenticated routes are still available
// (for registerAgent / activateAgent which need an owner identity).
func newPublicFixture(t *testing.T) *handlerFixture {
	t.Helper()
	fx := newHandlerFixture(t)
	pubH := handler.NewPublicHandler(fx.svc)
	fx.router.Get("/v2/public/agents", pubH.List)
	fx.router.Get("/v2/public/agents/{agentId}", pubH.Detail)
	return fx
}
