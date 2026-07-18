package ard

import "testing"

// TestMintURN pins the shared derivation both projection surfaces (the
// Finder's search results and the RA's published catalog) depend on:
// lowercased host, `agents` namespace, labelized display name, and the
// no-label refusal.
func TestMintURN(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		displayName string
		want        string
		ok          bool
	}{
		{"simple", "agent.example.com", "demo-agent", "urn:air:agent.example.com:agents:demo-agent", true},
		{"spaces collapse to hyphens", "agent.example.com", "Acme Support Agent", "urn:air:agent.example.com:agents:Acme-Support-Agent", true},
		{"host lowercased, label case kept", "AGENT.Example.COM", "CasePreserved", "urn:air:agent.example.com:agents:CasePreserved", true},
		{"internal whitespace runs", "a.example.com", "  spaced   out\tname ", "urn:air:a.example.com:agents:spaced-out-name", true},
		{"empty display name refused", "a.example.com", "", "", false},
		{"whitespace-only refused", "a.example.com", " \t ", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MintURN(tc.host, tc.displayName)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("MintURN(%q, %q) = (%q, %v), want (%q, %v)",
					tc.host, tc.displayName, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestLabelize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"demo-agent", "demo-agent"},
		{"Acme Support Agent", "Acme-Support-Agent"},
		{"  edges trimmed  ", "edges-trimmed"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range tests {
		if got := Labelize(tc.in); got != tc.want {
			t.Errorf("Labelize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
