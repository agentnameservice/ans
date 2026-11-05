package service

import "testing"

func TestAgentEventTransitionUsesTerminalDomainStates(t *testing.T) {
	states := []string{"AGENT_REGISTERED", "AGENT_RENEWED", "AGENT_DEPRECATED", "AGENT_REVOKED", "unknown"}
	for _, previous := range states {
		for _, incoming := range states {
			active := previous == "AGENT_REGISTERED" || previous == "AGENT_RENEWED"
			want := (active && (incoming == "AGENT_RENEWED" || incoming == "AGENT_DEPRECATED" || incoming == "AGENT_REVOKED")) ||
				(previous == "AGENT_DEPRECATED" && incoming == "AGENT_REVOKED")
			if got := agentEventTransitionAllowed(previous, incoming); got != want {
				t.Errorf("%s -> %s = %v, want %v", previous, incoming, got, want)
			}
		}
	}
}
