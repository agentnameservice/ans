package main

import (
	"strings"
	"testing"
)

// These tests pin the -fqdn binding reported in review on #131: the
// signature checks prove a registration was signed by the log, not that
// it is the registration for the hostname the caller asked about.
// `_ans-badge` is a TXT record under the queried name, so a name with no
// registration of its own can publish a badge pointing at another host's
// agentId — every signature then verifies while the receipt names a
// different host throughout.

func TestBindRequestedFQDN_RejectsAnotherHostsRegistration(t *testing.T) {
	t.Parallel()
	// The reported case: _ans-badge.unregistered.example points at a
	// valid registration for registered.example.
	payload := makeEnvelope("ans://v1.0.0.registered.example", "registered.example", "AGENT_REGISTERED")

	err := bindRequestedFQDN("unregistered.example", payload)
	if err == nil {
		t.Fatal("an unregistered host must not borrow another registration's proof")
	}
	for _, want := range []string{"unregistered.example", "registered.example"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %q so the operator can see the substitution", err, want)
		}
	}
}

func TestBindRequestedFQDN_AcceptsTheRequestedHost(t *testing.T) {
	t.Parallel()
	payload := makeEnvelope("ans://v1.0.0.agent.example.com", "agent.example.com", "AGENT_REGISTERED")

	for _, requested := range []string{
		"agent.example.com",
		"agent.example.com.", // rooted input normalizes to the same name
		"AGENT.Example.COM",  // DNS names are case-insensitive
	} {
		if err := bindRequestedFQDN(requested, payload); err != nil {
			t.Errorf("bindRequestedFQDN(%q): %v", requested, err)
		}
	}
}

// A sibling of the requested name is a different registration. Guards
// against a suffix or prefix comparison creeping in later.
func TestBindRequestedFQDN_RejectsRelatedNames(t *testing.T) {
	t.Parallel()
	payload := makeEnvelope("ans://v1.0.0.agent.example.com", "agent.example.com", "AGENT_REGISTERED")

	for _, requested := range []string{
		"sub.agent.example.com",
		"example.com",
		"notagent.example.com",
	} {
		if err := bindRequestedFQDN(requested, payload); err == nil {
			t.Errorf("bindRequestedFQDN(%q) accepted a different host's registration", requested)
		}
	}
}

// With agent.host absent the ansName carries the host, and it must be
// read with the registry's parser: the version segment holds dots, so a
// naive split on the first label would mis-slice v1.0.0 and compare the
// wrong name.
func TestBindRequestedFQDN_FallsBackToAnsName(t *testing.T) {
	t.Parallel()
	payload := makeEnvelope("ans://v1.0.0.agent.example.com", "", "AGENT_REGISTERED")

	if err := bindRequestedFQDN("agent.example.com", payload); err != nil {
		t.Errorf("ansName fallback should bind the host: %v", err)
	}
	if err := bindRequestedFQDN("0.agent.example.com", payload); err == nil {
		t.Error("a mis-sliced version segment must not be treated as part of the host")
	}
}

// Naming no host at all is a refusal, not a pass. An event the tool
// cannot bind is one it cannot report VERIFIED for in -fqdn mode.
func TestBindRequestedFQDN_RefusesWhenNoHostIsNamed(t *testing.T) {
	t.Parallel()
	for name, payload := range map[string][]byte{
		"neither field":   makeEnvelope("", "", "AGENT_REGISTERED"),
		"unparsable ans":  makeEnvelope("not-an-ans-name", "", "AGENT_REGISTERED"),
		"not an envelope": []byte(`{"payload":{}}`),
		"not json":        []byte("{"),
	} {
		if err := bindRequestedFQDN("agent.example.com", payload); err == nil {
			t.Errorf("%s: want a refusal, got nil", name)
		}
	}
}
