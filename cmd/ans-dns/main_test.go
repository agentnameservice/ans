package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// svcbValueKeyNNNNN is the DNS-AID-aligned SVCB presentation the RA's
// ANS_DNSAID profile emits: ServiceMode `1 .` plus alpn, port, the
// capability locator (key65400, a full https URL), the capability digest
// (key65401), the agent protocol (key65402), and the well-known suffix
// (key65409) — all RFC 9460 §14.3.1 Private Use keyNNNNN params. The
// keyNNNNN forms are what make the value publishable — see the named-form
// negative case below.
const (
	svcbValueKeyNNNNN = `1 . alpn=a2a port=443 key65400=https://agent.example.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json`
	// svcbValueCapQuery exercises a cap locator carrying a query string —
	// the `?` and `=` survive dns.NewRR and the serve path, proving the
	// metadataUrl-as-cap round-trip the DNS-AID conformance change relies on.
	svcbValueCapQuery = `1 . alpn=mcp port=443 key65400=https://agent.example.com/.well-known/mcp.json?v=2 key65402=mcp`
	// svcbValueNamedCap is the unpublishable named form. dns.NewRR rejects
	// it (`bad SVCB key`), so answersFor drops it and the server returns no
	// answer — the unpublishability the keyNNNNN choice rests on. ans-dns
	// serving this value is indistinguishable from NXDOMAIN to a resolver.
	svcbValueNamedCap = `1 . alpn=a2a port=443 cap=https://agent.example.com/.well-known/agent-card.json`
	tlsaValueSel0     = `3 0 1 deadbeefcafe1234`
	txtValue          = `v=ans1; version=1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a`
)

// TestAnswersFor_ServePathRoundTrip drives the serve path (answersFor)
// directly: each zone record is composed into a presentation line and
// parsed with dns.NewRR exactly as the running server does, so a value
// the parser rejects yields zero answers. Table-driven over the record
// shapes the RA emits post-Fix-A/B2.
func TestAnswersFor_ServePathRoundTrip(t *testing.T) {
	const fqdn = "agent.example.com"

	tests := []struct {
		name       string
		record     zoneRecord
		queryName  string
		queryType  uint16
		wantAnswer bool   // true → exactly one RR served
		wantInRR   string // substring required in the served RR string (when wantAnswer)
	}{
		{
			name:       "svcb_keyNNNNN_cap_locator_parses_and_serves",
			record:     zoneRecord{Name: fqdn, Type: "SVCB", Value: svcbValueKeyNNNNN, TTL: 3600},
			queryName:  fqdn,
			queryType:  dns.TypeSVCB,
			wantAnswer: true,
			// dns.NewRR re-renders Private Use SvcParams quoted; pin that
			// the cap URL (with `:` and `/`) survives the round-trip.
			wantInRR: `key65400="https://agent.example.com/.well-known/agent-card.json"`,
		},
		{
			name:       "svcb_keyNNNNN_carries_capability_digest_bap_and_well_known",
			record:     zoneRecord{Name: fqdn, Type: "SVCB", Value: svcbValueKeyNNNNN, TTL: 3600},
			queryName:  fqdn,
			queryType:  dns.TypeSVCB,
			wantAnswer: true,
			wantInRR:   `key65401="CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"`,
		},
		{
			name:       "svcb_cap_locator_with_query_string_round_trips",
			record:     zoneRecord{Name: fqdn, Type: "SVCB", Value: svcbValueCapQuery, TTL: 3600},
			queryName:  fqdn,
			queryType:  dns.TypeSVCB,
			wantAnswer: true,
			// The `?` and `=` of the query string survive parse + serve.
			wantInRR: `key65400="https://agent.example.com/.well-known/mcp.json?v=2"`,
		},
		{
			name:       "svcb_named_cap_rejected_and_dropped",
			record:     zoneRecord{Name: fqdn, Type: "SVCB", Value: svcbValueNamedCap, TTL: 3600},
			queryName:  fqdn,
			queryType:  dns.TypeSVCB,
			wantAnswer: false, // dns.NewRR("… cap=…") errors → answersFor skips it
		},
		{
			name:       "txt_value_served_quoted",
			record:     zoneRecord{Name: "_ans." + fqdn, Type: "TXT", Value: txtValue, TTL: 3600},
			queryName:  "_ans." + fqdn,
			queryType:  dns.TypeTXT,
			wantAnswer: true,
			wantInRR:   `"` + txtValue + `"`,
		},
		{
			name:       "tlsa_selector0_served",
			record:     zoneRecord{Name: "_443._tcp." + fqdn, Type: "TLSA", Value: tlsaValueSel0, TTL: 3600},
			queryName:  "_443._tcp." + fqdn,
			queryType:  dns.TypeTLSA,
			wantAnswer: true,
			wantInRR:   "3 0 1 deadbeefcafe1234",
		},
		{
			name:       "type_mismatch_yields_no_answer",
			record:     zoneRecord{Name: fqdn, Type: "SVCB", Value: svcbValueKeyNNNNN, TTL: 3600},
			queryName:  fqdn,
			queryType:  dns.TypeA, // querying A against an SVCB record
			wantAnswer: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := dns.Question{Name: dns.Fqdn(tc.queryName), Qtype: tc.queryType, Qclass: dns.ClassINET}
			answers := answersFor(q, []zoneRecord{tc.record})

			if !tc.wantAnswer {
				if len(answers) != 0 {
					t.Fatalf("want zero answers, got %d: %v", len(answers), answers)
				}
				return
			}
			if len(answers) != 1 {
				t.Fatalf("want exactly one answer, got %d: %v", len(answers), answers)
			}
			got := answers[0].String()
			if tc.wantInRR != "" && !strings.Contains(got, tc.wantInRR) {
				t.Errorf("served RR %q does not contain %q", got, tc.wantInRR)
			}
		})
	}
}

// TestLoadZoneThenServe pins the full disk-to-wire path: a JSON zone
// file written by `install` is loaded by loadZone, flattened, and
// served by answersFor. Exercises the keyNNNNN SVCB and selector-0 TLSA
// records together as one agent's record set, the way an operator
// publishes them.
func TestLoadZoneThenServe(t *testing.T) {
	const fqdn = "agent.example.com"
	dir := t.TempDir()
	zonePath := filepath.Join(dir, "zone.json")

	zoneJSON := `{
  "records": {
    "agent-1": [
      {"name": "agent.example.com", "type": "SVCB", "value": "1 . alpn=a2a port=443 key65400=https://agent.example.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json", "ttl": 3600},
      {"name": "_443._tcp.agent.example.com", "type": "TLSA", "value": "3 0 1 deadbeefcafe1234", "ttl": 3600}
    ]
  }
}`
	if err := os.WriteFile(zonePath, []byte(zoneJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	z, err := loadZone(zonePath)
	if err != nil {
		t.Fatalf("loadZone: %v", err)
	}
	records := z.flatten()
	if len(records) != 2 {
		t.Fatalf("want 2 flattened records, got %d", len(records))
	}

	svcb := answersFor(dns.Question{Name: dns.Fqdn(fqdn), Qtype: dns.TypeSVCB, Qclass: dns.ClassINET}, records)
	if len(svcb) != 1 {
		t.Fatalf("want one SVCB answer, got %d", len(svcb))
	}
	if !strings.Contains(svcb[0].String(), `key65400="https://agent.example.com/.well-known/agent-card.json"`) {
		t.Errorf("SVCB answer missing key65400 cap locator after disk round-trip: %q", svcb[0].String())
	}
	if !strings.Contains(svcb[0].String(), `key65401="CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"`) {
		t.Errorf("SVCB answer missing key65401 capability digest after disk round-trip: %q", svcb[0].String())
	}

	tlsa := answersFor(dns.Question{Name: dns.Fqdn("_443._tcp." + fqdn), Qtype: dns.TypeTLSA, Qclass: dns.ClassINET}, records)
	if len(tlsa) != 1 {
		t.Fatalf("want one TLSA answer, got %d", len(tlsa))
	}
	if !strings.Contains(tlsa[0].String(), "3 0 1 deadbeefcafe1234") {
		t.Errorf("TLSA answer missing selector-0 binding: %q", tlsa[0].String())
	}
}

// TestLoadZoneMissingFileIsEmpty pins loadZone's "no file → empty zone"
// contract that lets `serve` start before any `install` has run.
func TestLoadZoneMissingFileIsEmpty(t *testing.T) {
	z, err := loadZone(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("loadZone on missing file must not error, got %v", err)
	}
	if len(z.flatten()) != 0 {
		t.Errorf("missing-file zone must be empty, got %d records", len(z.flatten()))
	}
}
