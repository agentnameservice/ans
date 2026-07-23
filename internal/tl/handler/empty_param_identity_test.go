package handler_test

// Empty-path-param guards for the identity read surface — siblings of
// the agent-route cases in empty_param_test.go. Each guard fires
// before any service is touched, so a fully-nil Handlers suffices.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentnameservice/ans/internal/tl/handler"
)

func TestIdentityRoutes_EmptyParams(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)

	cases := []struct {
		name    string
		param   string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"identity badge", "identityId", "/v1/identities/", h.GetIdentityBadge},
		{"identity audit", "identityId", "/v1/identities//audit", h.GetIdentityAudit},
		{"identity receipt", "identityId", "/v1/identities//receipt", h.GetIdentityReceipt},
		{"identity agents", "identityId", "/v1/identities//agents", h.GetIdentityAgents},
		{"agent identities", "agentId", "/v1/agents//identities", h.GetAgentIdentities},
		{"agent identity history", "agentId", "/v1/agents//identities/history", h.GetAgentIdentityHistory},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			tc.handler(rec, emptyParamReq(http.MethodGet, tc.path, tc.param))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status: got %d want 422", rec.Code)
			}
		})
	}
}
