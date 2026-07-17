package catalog

import (
	"encoding/json"
	"testing"

	"github.com/godaddy/ans/internal/domain"
)

// activeReg builds an ACTIVE registration on the given host/version with a
// single eligible MCP endpoint (metaDataUrl on the same host).
func activeReg(t *testing.T, host, version string) *domain.AgentRegistration {
	t.Helper()
	reg := newRegHost(t, host, version, domain.AgentEndpoint{
		Protocol:    domain.ProtocolMCP,
		AgentURL:    "https://" + host + "/mcp",
		MetadataURL: "https://" + host + "/.well-known/mcp/server-card.json",
	})
	reg.Status = domain.StatusActive
	return reg
}

func TestBuildHostDocument_HostObjectAndEntries(t *testing.T) {
	host := "ai-agent.acme.example.com"
	regs := []*domain.AgentRegistration{activeReg(t, host, "1.0.0")}

	doc := BuildHostDocument(host, regs, Options{TLPublicBaseURL: testTLBase})

	if doc.SpecVersion != SpecVersion {
		t.Errorf("specVersion = %q, want %q", doc.SpecVersion, SpecVersion)
	}
	if doc.Host == nil || doc.Host.Identifier != host || doc.Host.DisplayName != host {
		t.Errorf("host object = %+v, want identifier=displayName=%q", doc.Host, host)
	}
	if len(doc.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(doc.Entries))
	}
	if doc.Entries[0].Identifier != "urn:air:"+host+":agents:Acme-Support-Agent" {
		t.Errorf("entry identifier = %q", doc.Entries[0].Identifier)
	}

	// host.displayName MUST be present on the wire even though it equals
	// the identifier (§4.1).
	if js := mustJSON(t, doc); !contains(js, `"displayName":"`+host+`"`) {
		t.Errorf("host.displayName must serialize: %s", js)
	}
}

func TestBuildHostDocument_OnlyActiveEligible(t *testing.T) {
	host := "h.example.com"

	active := activeReg(t, host, "1.0.0")

	pending := activeReg(t, host, "1.1.0")
	pending.Status = domain.StatusPendingValidation // excluded: not ACTIVE

	deprecated := activeReg(t, host, "0.9.0")
	deprecated.Status = domain.StatusDeprecated // excluded: AHPs prune from well-known (§8)

	revoked := activeReg(t, host, "0.8.0")
	revoked.Status = domain.StatusRevoked // excluded

	// ACTIVE but ineligible (no metaDataUrl) → absent.
	ineligible := newRegHost(t, host, "2.0.0", domain.AgentEndpoint{
		Protocol: domain.ProtocolMCP,
		AgentURL: "https://" + host + "/mcp",
	})
	ineligible.Status = domain.StatusActive

	doc := BuildHostDocument(host, []*domain.AgentRegistration{
		pending, active, deprecated, revoked, ineligible,
	}, Options{TLPublicBaseURL: testTLBase})

	if len(doc.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (only the ACTIVE eligible agent)", len(doc.Entries))
	}
	if doc.Entries[0].Version != "1.0.0" {
		t.Errorf("entry version = %q, want 1.0.0", doc.Entries[0].Version)
	}
}

func TestBuildHostDocument_MultiVersionSortedAndStable(t *testing.T) {
	host := "h.example.com"
	// Supply versions out of order; expect deterministic (identifier,
	// version) ordering so the ETag is reproducible.
	regs := []*domain.AgentRegistration{
		activeReg(t, host, "2.0.0"),
		activeReg(t, host, "1.0.0"),
		activeReg(t, host, "1.2.0"),
	}
	doc := BuildHostDocument(host, regs, Options{TLPublicBaseURL: testTLBase})
	if len(doc.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(doc.Entries))
	}
	got := []string{doc.Entries[0].Version, doc.Entries[1].Version, doc.Entries[2].Version}
	want := []string{"1.0.0", "1.2.0", "2.0.0"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("version order = %v, want %v", got, want)
		}
	}
	// Same inputs → identical bytes (ETag stability).
	doc2 := BuildHostDocument(host, []*domain.AgentRegistration{
		activeReg(t, host, "1.2.0"), activeReg(t, host, "2.0.0"), activeReg(t, host, "1.0.0"),
	}, Options{TLPublicBaseURL: testTLBase})
	if mustJSON(t, doc) != mustJSON(t, doc2) {
		t.Error("documents from the same registrations (different input order) must serialize identically")
	}
}

func TestBuildHostDocument_EmptyWhenNoEligible(t *testing.T) {
	host := "empty.example.com"
	// One PENDING, one ACTIVE-but-ineligible → no entries, but the
	// document is still well-formed (specVersion + host + empty entries).
	pending := activeReg(t, host, "1.0.0")
	pending.Status = domain.StatusPendingDNS

	doc := BuildHostDocument(host, []*domain.AgentRegistration{pending}, Options{})
	if doc.SpecVersion != SpecVersion || doc.Host == nil {
		t.Fatalf("document must stay well-formed when empty: %+v", doc)
	}
	if len(doc.Entries) != 0 {
		t.Errorf("entries = %d, want 0", len(doc.Entries))
	}
	// entries MUST serialize as [] (not null) so consumers can iterate.
	if js := mustJSON(t, doc); !contains(js, `"entries":[]`) {
		t.Errorf("empty entries must marshal as []: %s", js)
	}
}

func TestBuildHostDocument_NilRegSkipped(t *testing.T) {
	host := "h.example.com"
	doc := BuildHostDocument(host, []*domain.AgentRegistration{nil, activeReg(t, host, "1.0.0")}, Options{TLPublicBaseURL: testTLBase})
	if len(doc.Entries) != 1 {
		t.Fatalf("nil registration must be skipped; entries = %d", len(doc.Entries))
	}
}

// TestSortEntries exercises sortEntries directly, including the
// distinct-identifier branch that a single-host document never hits (one
// host = one lineage label) but the slice-3 multi-host export will.
func TestSortEntries(t *testing.T) {
	entries := []Entry{
		{Identifier: "urn:air:b.example.com:agents:b", Version: "1.0.0"},
		{Identifier: "urn:air:a.example.com:agents:a", Version: "2.0.0"},
		{Identifier: "urn:air:a.example.com:agents:a", Version: "1.0.0"},
	}
	sortEntries(entries)
	want := []struct{ id, ver string }{
		{"urn:air:a.example.com:agents:a", "1.0.0"},
		{"urn:air:a.example.com:agents:a", "2.0.0"},
		{"urn:air:b.example.com:agents:b", "1.0.0"},
	}
	for i, w := range want {
		if entries[i].Identifier != w.id || entries[i].Version != w.ver {
			t.Fatalf("entry %d = (%q,%q), want (%q,%q)", i, entries[i].Identifier, entries[i].Version, w.id, w.ver)
		}
	}
}

// guard: a freshly built host document round-trips through encoding/json
// without error (used by the handler to compute the ETag + body).
func TestBuildHostDocument_Marshalable(t *testing.T) {
	host := "h.example.com"
	doc := BuildHostDocument(host, []*domain.AgentRegistration{activeReg(t, host, "1.0.0")}, Options{TLPublicBaseURL: testTLBase})
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
