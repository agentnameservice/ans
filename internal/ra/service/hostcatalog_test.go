package service

// White-box tests for HostRegistrations' owner scoping — the
// defense-in-depth that backs the FQDN-exclusivity registration invariant.
// The invariant (RegisterAgent + VerifyDNS) prevents two owners from ever
// holding a live registration on one host via the API, but the catalog
// read must not depend on that being enforced elsewhere: even if a
// multi-owner host somehow existed (legacy data, a future invariant gap),
// one owner's per-host document must never include another owner's agent.
// Fakes let us construct exactly that otherwise-unreachable state.

import (
	"context"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// fakeHostAgentStore implements port.AgentStore but only FindAllByAgentHost;
// the embedded nil interface makes any other call panic (none are reached).
type fakeHostAgentStore struct {
	port.AgentStore
	byHost map[string][]*domain.AgentRegistration
}

func (f *fakeHostAgentStore) FindAllByAgentHost(_ context.Context, host string) ([]*domain.AgentRegistration, error) {
	return f.byHost[host], nil
}

// fakeEndpointStore implements port.EndpointStore but only FindByAgentIDs.
type fakeEndpointStore struct {
	port.EndpointStore
	byID map[string]*domain.AgentEndpoints
}

func (f *fakeEndpointStore) FindByAgentIDs(_ context.Context, ids []string) (map[string]*domain.AgentEndpoints, error) {
	out := make(map[string]*domain.AgentEndpoints, len(ids))
	for _, id := range ids {
		if e, ok := f.byID[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

func reg(agentID, ownerID, host string, status domain.RegistrationStatus) *domain.AgentRegistration {
	sv, _ := domain.ParseSemVer("1.0.0")
	ans, _ := domain.NewAnsName(sv, host)
	return &domain.AgentRegistration{AgentID: agentID, OwnerID: ownerID, AnsName: ans, Status: status}
}

func TestHostRegistrations_ScopesToRequestingOwner(t *testing.T) {
	const host = "shared.example.com"
	aliceA := reg("a-1", "alice", host, domain.StatusActive)
	bobA := reg("b-1", "bob", host, domain.StatusActive)

	svc := &RegistrationService{
		agents: &fakeHostAgentStore{byHost: map[string][]*domain.AgentRegistration{
			host: {aliceA, bobA},
		}},
		endpoints: &fakeEndpointStore{byID: map[string]*domain.AgentEndpoints{
			"a-1": {AgentID: "a-1", Endpoints: []domain.AgentEndpoint{{Protocol: domain.ProtocolMCP, AgentURL: "https://" + host + "/mcp"}}},
			"b-1": {AgentID: "b-1", Endpoints: []domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://" + host + "/a2a"}}},
		}},
	}

	got, err := svc.HostRegistrations(context.Background(), "alice", host)
	if err != nil {
		t.Fatalf("HostRegistrations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("returned %d registrations, want 1 (alice's only — bob's must not surface)", len(got))
	}
	if got[0].AgentID != "a-1" || got[0].OwnerID != "alice" {
		t.Errorf("returned %+v, want alice's a-1", got[0])
	}
	// Endpoints stamped onto the owner's registration.
	if len(got[0].Endpoints) != 1 || got[0].Endpoints[0].Protocol != domain.ProtocolMCP {
		t.Errorf("endpoints not stamped correctly: %+v", got[0].Endpoints)
	}
}

func TestHostRegistrations_EmptyWhenOwnerHasNoneOnHost(t *testing.T) {
	const host = "shared.example.com"
	svc := &RegistrationService{
		agents: &fakeHostAgentStore{byHost: map[string][]*domain.AgentRegistration{
			host: {reg("b-1", "bob", host, domain.StatusActive)},
		}},
		endpoints: &fakeEndpointStore{},
	}
	got, err := svc.HostRegistrations(context.Background(), "alice", host)
	if err != nil {
		t.Fatalf("HostRegistrations: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("alice owns nothing on the host; want 0 registrations, got %d", len(got))
	}
}

func TestHoldsHostExclusivity(t *testing.T) {
	cases := map[domain.RegistrationStatus]bool{
		domain.StatusActive:            true,
		domain.StatusDeprecated:        true,
		domain.StatusPendingValidation: false,
		domain.StatusPendingDNS:        false,
		domain.StatusRevoked:           false,
		domain.StatusExpired:           false,
		domain.StatusFailed:            false,
	}
	for st, want := range cases {
		if got := holdsHostExclusivity(st); got != want {
			t.Errorf("holdsHostExclusivity(%s) = %v, want %v", st, got, want)
		}
	}
}

func TestHostHeldByAnotherOwner(t *testing.T) {
	const host = "h.example.com"
	ctx := context.Background()
	withRegs := func(regs ...*domain.AgentRegistration) *RegistrationService {
		return &RegistrationService{agents: &fakeHostAgentStore{
			byHost: map[string][]*domain.AgentRegistration{host: regs},
		}}
	}

	tests := []struct {
		name          string
		regs          []*domain.AgentRegistration
		ownerID       string
		exceptAgentID string
		want          bool
	}{
		{"different owner ACTIVE holds", []*domain.AgentRegistration{reg("b-1", "bob", host, domain.StatusActive)}, "alice", "", true},
		{"different owner DEPRECATED holds", []*domain.AgentRegistration{reg("b-1", "bob", host, domain.StatusDeprecated)}, "alice", "", true},
		{"different owner only pending/terminal does not hold", []*domain.AgentRegistration{
			reg("b-1", "bob", host, domain.StatusPendingDNS),
			reg("b-2", "bob", host, domain.StatusRevoked),
		}, "alice", "", false},
		{"same owner does not block self", []*domain.AgentRegistration{reg("a-1", "alice", host, domain.StatusActive)}, "alice", "", false},
		// Load-bearing except case: a DIFFERENT owner's holding reg that
		// would otherwise return true is skipped because it is the excepted
		// agent — exercising the exceptAgentID branch, not the owner match.
		{"exceptAgentID skips an otherwise-holding different-owner reg", []*domain.AgentRegistration{reg("b-1", "bob", host, domain.StatusActive)}, "alice", "b-1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			held, err := withRegs(tc.regs...).hostHeldByAnotherOwner(ctx, host, tc.ownerID, tc.exceptAgentID)
			if err != nil {
				t.Fatalf("hostHeldByAnotherOwner: %v", err)
			}
			if held != tc.want {
				t.Errorf("held = %v, want %v", held, tc.want)
			}
		})
	}
}
