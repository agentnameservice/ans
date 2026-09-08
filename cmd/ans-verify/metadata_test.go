package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// envelopeWithAttestations wraps an attestations JSON object in the
// envelope path the receipt payload uses
// (payload.producer.event.attestations).
func envelopeWithAttestations(attestations string) []byte {
	return []byte(`{"schemaVersion":"V2","payload":{"producer":{"event":{` +
		`"eventType":"AGENT_REGISTERED","attestations":` + attestations + `}}}}`)
}

func sha256Tag(body string) string {
	sum := sha256.Sum256([]byte(body))
	return metadataHashPrefix + hex.EncodeToString(sum[:])
}

func TestMetadataChecksFromEvent_V2PairsHashWithSVCBRow(t *testing.T) {
	t.Parallel()
	payload := envelopeWithAttestations(`{
		"metadataHashes":{"A2A":"SHA256:aa","HTTP_API":"SHA256:bb","MCP":"SHA256:cc"},
		"dnsRecordsProvisioned":[
			{"name":"agent.example.com","type":"HTTPS","data":"1 . alpn=a2a port=443 key65400=https://agent.example.com/.well-known/agent.json key65401=x key65402=a2a"},
			{"name":"agent.example.com","type":"HTTPS","data":"1 . alpn=x-http port=443 key65400=https://agent.example.com/openapi.json key65402=x-http"},
			{"name":"agent.example.com","type":"HTTPS","data":"1 . alpn=mcp port=443 key65402=mcp"},
			{"name":"_ans.agent.example.com","type":"TXT","data":"v=ans1 key65400=https://not-a-svcb-row.example"}
		]}`)
	checks, err := metadataChecksFromEvent(payload)
	if err != nil {
		t.Fatalf("metadataChecksFromEvent: %v", err)
	}
	want := []metadataCheck{
		{Protocol: "A2A", URL: "https://agent.example.com/.well-known/agent.json", WantHash: "SHA256:aa"},
		{Protocol: "HTTP_API", URL: "https://agent.example.com/openapi.json", WantHash: "SHA256:bb"},
		{Protocol: "MCP", URL: "", WantHash: "SHA256:cc"}, // row has no key65400
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i := range want {
		if checks[i] != want[i] {
			t.Errorf("check %d = %+v, want %+v", i, checks[i], want[i])
		}
	}
}

func TestMetadataChecksFromEvent_V1MapShape(t *testing.T) {
	t.Parallel()
	payload := envelopeWithAttestations(`{
		"metadataHashes":{"MCP":"SHA256:cc"},
		"dnsRecordsProvisioned":{
			"agent.example.com":"1 . alpn=mcp port=443 key65400=https://agent.example.com/mcp.json key65402=mcp",
			"_ans.agent.example.com":"v=ans1"
		}}`)
	checks, err := metadataChecksFromEvent(payload)
	if err != nil {
		t.Fatalf("metadataChecksFromEvent: %v", err)
	}
	if len(checks) != 1 || checks[0].URL != "https://agent.example.com/mcp.json" {
		t.Fatalf("got %+v, want one MCP check with the V1-map URL", checks)
	}
}

func TestMetadataChecksFromEvent_NoHashesMeansNothingToCheck(t *testing.T) {
	t.Parallel()
	for name, att := range map[string]string{
		"absent": `{"domainValidation":"ACME-DNS-01"}`,
		"empty":  `{"metadataHashes":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checks, err := metadataChecksFromEvent(envelopeWithAttestations(att))
			if err != nil || checks != nil {
				t.Fatalf("got (%v, %v), want (nil, nil)", checks, err)
			}
		})
	}
}

func TestMetadataChecksFromEvent_BadJSON(t *testing.T) {
	t.Parallel()
	if _, err := metadataChecksFromEvent([]byte(`{not json`)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDecodeAttestedRecords_UnknownShapeIsEmpty(t *testing.T) {
	t.Parallel()
	if got := decodeAttestedRecords([]byte(`42`)); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
	if got := decodeAttestedRecords(nil); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

func TestDescriptorURLsByToken_BAPAloneAndFirstRowWins(t *testing.T) {
	t.Parallel()
	urls := descriptorURLsByToken([]attestedRecord{
		{Type: "SVCB", Data: "1 . port=443 key65400=https://a.example/one key65402=A2A"},
		{Type: "SVCB", Data: "1 . alpn=a2a port=8443 key65400=https://a.example/two key65402=a2a"},
		{Type: "TLSA", Data: "3 1 1 deadbeef"},
	})
	if urls["a2a"] != "https://a.example/one" {
		t.Fatalf("a2a → %q, want the first row's URL (bap-only, case-folded)", urls["a2a"])
	}
	if len(urls) != 1 {
		t.Fatalf("urls = %v, want exactly one token", urls)
	}
}

func TestDNSAIDTokenForProtocol(t *testing.T) {
	t.Parallel()
	cases := map[string]string{"A2A": "a2a", "MCP": "mcp", "HTTP_API": "x-http", "http_api": "x-http"}
	for in, want := range cases {
		if got := dnsaidTokenForProtocol(in); got != want {
			t.Errorf("dnsaidTokenForProtocol(%q) = %q, want %q", in, got, want)
		}
	}
}

// descriptorServer serves a fixed document at /card.json and 401s
// everything else.
func descriptorServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/card.json" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyMetadata_Outcomes(t *testing.T) {
	t.Parallel()
	const doc = `{"name":"agent","capabilities":["pay"]}`
	srv := descriptorServer(t, doc)
	checks := []metadataCheck{
		{Protocol: "A2A", URL: srv.URL + "/card.json", WantHash: strings.ToUpper(sha256Tag(doc))},
		{Protocol: "MCP", URL: srv.URL + "/card.json", WantHash: sha256Tag("something else")},
		{Protocol: "HTTP_API", URL: srv.URL + "/private.json", WantHash: sha256Tag(doc)},
		{Protocol: "X", URL: "", WantHash: sha256Tag(doc)},
	}
	results := verifyMetadata(context.Background(), srv.Client(), checks)
	want := []metadataOutcome{metadataMatch, metadataMismatch, metadataUnreachable, metadataNoURL}
	for i, r := range results {
		if r.Outcome != want[i] {
			t.Errorf("%s: outcome %d, want %d (err=%v)", r.Protocol, r.Outcome, want[i], r.Err)
		}
	}
	if results[0].GotHash != sha256Tag(doc) {
		t.Errorf("match GotHash = %s, want %s", results[0].GotHash, sha256Tag(doc))
	}
	if results[2].Err == nil || !strings.Contains(results[2].Err.Error(), "HTTP 401") {
		t.Errorf("unreachable err = %v, want HTTP 401", results[2].Err)
	}
}

func TestFetchDescriptor_BodyCapped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("x", 1<<20)
		for range (maxResponseBytes >> 20) + 1 {
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	if _, err := fetchDescriptor(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected body-cap error")
	}
}

func TestFetchDescriptor_BadURL(t *testing.T) {
	t.Parallel()
	if _, err := fetchDescriptor(context.Background(), http.DefaultClient, "://bad"); err == nil {
		t.Fatal("expected request-build error")
	}
}

func TestRunMetadataStep_Disabled(t *testing.T) {
	t.Parallel()
	if runMetadataStep(context.Background(), nil, false, time.Second) {
		t.Fatal("disabled step must not fail")
	}
}

func TestRunMetadataStep_UnparsableReceiptDoesNotFail(t *testing.T) {
	t.Parallel()
	if runMetadataStep(context.Background(), []byte("not a receipt"), true, time.Second) {
		t.Fatal("unparsable receipt must report, not fail")
	}
}

func TestPrintMetadataResult_CoversEveryOutcome(t *testing.T) {
	t.Parallel()
	for _, o := range []metadataOutcome{metadataMatch, metadataMismatch, metadataUnreachable, metadataNoURL} {
		printMetadataResult(metadataResult{
			metadataCheck: metadataCheck{Protocol: "A2A", URL: "https://x", WantHash: "SHA256:aa"},
			Outcome:       o, GotHash: "SHA256:bb", Err: errors.New("HTTP 401"),
		})
	}
}

func TestMetadataStepForPayload_FailsOnlyOnMismatch(t *testing.T) {
	t.Parallel()
	const doc = `{"name":"agent"}`
	srv := descriptorServer(t, doc)
	row := func(alpn, url string) string {
		return `{"name":"agent.example.com","type":"HTTPS","data":"1 . alpn=` + alpn +
			` port=443 key65400=` + url + ` key65402=` + alpn + `"}`
	}
	cases := map[string]struct {
		attestations string
		wantFail     bool
	}{
		"match": {
			`{"metadataHashes":{"A2A":"` + sha256Tag(doc) + `"},"dnsRecordsProvisioned":[` +
				row("a2a", srv.URL+"/card.json") + `]}`, false},
		"mismatch": {
			`{"metadataHashes":{"A2A":"` + sha256Tag("other") + `"},"dnsRecordsProvisioned":[` +
				row("a2a", srv.URL+"/card.json") + `]}`, true},
		"unreachable is reported not failed": {
			`{"metadataHashes":{"A2A":"` + sha256Tag(doc) + `"},"dnsRecordsProvisioned":[` +
				row("a2a", srv.URL+"/private.json") + `]}`, false},
		"no url is reported not failed": {
			`{"metadataHashes":{"A2A":"` + sha256Tag(doc) + `"},"dnsRecordsProvisioned":[]}`, false},
		"nothing attested": {`{}`, false},
		"mismatch beside a match still fails": {
			`{"metadataHashes":{"A2A":"` + sha256Tag(doc) + `","MCP":"` + sha256Tag("other") +
				`"},"dnsRecordsProvisioned":[` + row("a2a", srv.URL+"/card.json") + `,` +
				row("mcp", srv.URL+"/card.json") + `]}`, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := metadataStepForPayload(context.Background(), envelopeWithAttestations(c.attestations), srv.Client())
			if got != c.wantFail {
				t.Fatalf("failed = %v, want %v", got, c.wantFail)
			}
		})
	}
}

func TestMetadataStepForPayload_BadPayloadDoesNotFail(t *testing.T) {
	t.Parallel()
	if metadataStepForPayload(context.Background(), []byte("{"), http.DefaultClient) {
		t.Fatal("undecodable payload must report, not fail")
	}
}
