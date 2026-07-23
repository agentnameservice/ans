package ans

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentnameservice/ans/internal/domain"
)

func TestBadgeRecord(t *testing.T) {
	mustReg := func(t *testing.T, version string, host string, eps []domain.AgentEndpoint) *domain.AgentRegistration {
		t.Helper()
		v, err := domain.ParseSemVer(version)
		require.NoError(t, err)
		ansName, err := domain.NewAnsName(v, host)
		require.NoError(t, err)
		return &domain.AgentRegistration{AnsName: ansName, Endpoints: eps}
	}

	tests := []struct {
		name      string
		reg       *domain.AgentRegistration
		agentID   string
		tlBaseURL string
		wantEmpty bool
		wantName  string
		wantValue string
	}{
		{
			name:      "no_endpoints_emits_no_badge",
			reg:       mustReg(t, "1.0.0", "agent.example.com", nil),
			wantEmpty: true,
		},
		{
			name: "single_endpoint_emits_one_badge",
			reg: mustReg(t, "1.2.3", "agent.example.com", []domain.AgentEndpoint{
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
			}),
			wantName:  "_ans-badge.agent.example.com",
			wantValue: "v=ans-badge1; version=v1.2.3; url=https://agent.example.com/a2a",
		},
		{
			name: "multiple_endpoints_badge_uses_first_url",
			reg: mustReg(t, "2.0.0", "agent.example.com", []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
				{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com/a2a"},
			}),
			wantName:  "_ans-badge.agent.example.com",
			wantValue: "v=ans-badge1; version=v2.0.0; url=https://agent.example.com/mcp",
		},
		{
			// When the deployment supplies a public TL URL and the
			// registration carries an AgentID, the badge url= points at the
			// TL's per-agent badge endpoint rather than the agent's own host
			// — badge verifiers resolve trust through the log, not the agent.
			name: "tl_base_url_points_badge_at_transparency_log",
			reg: mustReg(t, "1.0.0", "agent.example.com", []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			}),
			agentID:   "test-agent-id",
			tlBaseURL: "https://tl.example.org",
			wantName:  "_ans-badge.agent.example.com",
			wantValue: "v=ans-badge1; version=v1.0.0; url=https://tl.example.org/v1/agents/test-agent-id",
		},
		{
			// Fallback: a TL URL is set but the registration has no AgentID,
			// so the per-agent TL path can't be formed and the badge falls
			// back to the first endpoint's URL.
			name: "tl_base_url_without_agent_id_falls_back_to_endpoint",
			reg: mustReg(t, "1.0.0", "agent.example.com", []domain.AgentEndpoint{
				{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
			}),
			tlBaseURL: "https://tl.example.org",
			wantName:  "_ans-badge.agent.example.com",
			wantValue: "v=ans-badge1; version=v1.0.0; url=https://agent.example.com/mcp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.reg.AgentID = tc.agentID
			got := BadgeRecord(tc.reg, tc.tlBaseURL)
			if tc.wantEmpty {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			r := got[0]
			assert.Equal(t, tc.wantName, r.Name)
			assert.Equal(t, domain.DNSRecordTXT, r.Type)
			assert.Equal(t, tc.wantValue, r.Value)
			assert.Equal(t, domain.PurposeBadge, r.Purpose)
			assert.True(t, r.Required, "_ans-badge is always Required=true alongside discovery records")
			assert.Equal(t, 3600, r.TTL)
		})
	}
}
