package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/godaddy/ans/internal/domain"
)

// ----- NoopVerifier -----

func TestNoopVerifier_AllRequiredTrueEvenWithZeroExpected(t *testing.T) {
	t.Parallel()
	v := NewNoopVerifier()
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.AllRequired {
		t.Error("NoopVerifier must report AllRequired=true for any input")
	}
	if len(got.Results) != 0 {
		t.Errorf("empty expected should yield empty results, got %d", len(got.Results))
	}
}

func TestNoopVerifier_MarksAllRecordsFound(t *testing.T) {
	t.Parallel()
	v := NewNoopVerifier()
	expected := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v1", Required: true},
		{Name: "_ans-tlsa.agent.example.com", Type: domain.DNSRecordTLSA, Value: "hash", Required: false},
	}
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", expected)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.AllRequired {
		t.Error("want AllRequired=true")
	}
	if len(got.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(got.Results))
	}
	for i, r := range got.Results {
		if !r.Found {
			t.Errorf("result %d should be Found=true", i)
		}
		if r.Actual != expected[i].Value {
			t.Errorf("result %d actual: got %q, want %q", i, r.Actual, expected[i].Value)
		}
	}
}

// ----- LookupVerifier -----

// testServer stands up an in-process miekg/dns UDP server backed by a
// per-name answer map. Each test builds a tiny zone, points the
// verifier at the server's address, and asserts per-record results.
//
// The handler goroutine reads `answers` and `ad` concurrently with
// test-goroutine writes via `add()` / direct field assignment, so
// both fields are guarded by `mu`. The race detector flagged the
// unsynchronized access before this lock landed.
type testServer struct {
	addr    string
	mu      sync.RWMutex
	answers map[string][]miekg.RR
	ad      bool // set AuthenticatedData on replies to simulate a DNSSEC-validating resolver
	srv     *miekg.Server
	stop    func()
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	s := &testServer{answers: map[string][]miekg.RR{}}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.addr = pc.LocalAddr().String()

	mux := miekg.NewServeMux()
	mux.HandleFunc(".", func(w miekg.ResponseWriter, req *miekg.Msg) {
		m := new(miekg.Msg)
		m.SetReply(req)
		m.Authoritative = true
		s.mu.RLock()
		m.AuthenticatedData = s.ad
		if len(req.Question) > 0 {
			q := req.Question[0]
			key := strings.ToLower(q.Name) + ":" + miekg.TypeToString[q.Qtype]
			m.Answer = append(m.Answer, s.answers[key]...)
			if len(m.Answer) == 0 {
				m.Rcode = miekg.RcodeNameError
			}
		}
		s.mu.RUnlock()
		_ = w.WriteMsg(m)
	})

	s.srv = &miekg.Server{PacketConn: pc, Handler: mux}
	done := make(chan struct{})
	go func() {
		_ = s.srv.ActivateAndServe()
		close(done)
	}()
	s.stop = func() {
		_ = s.srv.Shutdown()
		<-done
	}
	t.Cleanup(s.stop)
	// Small wait so the goroutine is ready to accept packets.
	time.Sleep(20 * time.Millisecond)
	return s
}

func (s *testServer) add(name, typ, rrString string) {
	rr, err := miekg.NewRR(rrString)
	if err != nil {
		panic("testServer.add: bad RR: " + err.Error())
	}
	key := strings.ToLower(miekg.Fqdn(name)) + ":" + typ
	s.mu.Lock()
	s.answers[key] = append(s.answers[key], rr)
	s.mu.Unlock()
}

// setAD toggles the simulated DNSSEC AuthenticatedData bit. Tests
// that mutate this field after the server is running should call
// this rather than assigning directly so the change is published
// safely to the handler goroutine.
func (s *testServer) setAD(ad bool) {
	s.mu.Lock()
	s.ad = ad
	s.mu.Unlock()
}

// verifyAgainst runs the verifier against this test server and
// returns the per-record results.
func (s *testServer) verifyAgainst(t *testing.T, recs []domain.ExpectedDNSRecord) []miekgResult {
	t.Helper()
	v := NewLookupVerifier(WithServer(s.addr), WithTimeout(2*time.Second))
	res, err := v.VerifyRecords(context.Background(), "agent.example.com", recs)
	if err != nil {
		t.Fatalf("VerifyRecords: %v", err)
	}
	out := make([]miekgResult, len(res.Results))
	for i, r := range res.Results {
		out[i] = miekgResult{r.Record.Type, r.Found, r.DNSSECVerified, r.Actual, r.Error}
	}
	return out
}

type miekgResult struct {
	typ       domain.DNSRecordType
	found     bool
	dnssec    bool
	actual    string
	errString string
}

func TestLookupVerifier_TXTMatchAndMismatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.add("_ans.agent.example.com.", "TXT", `_ans.agent.example.com. 3600 IN TXT "v=ans1; version=1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a"`)

	recs := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT,
			Value: "v=ans1; version=1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a", Required: true},
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT,
			Value: "v=ans1; version=9.9.9; p=mcp", Required: true},
	}
	got := s.verifyAgainst(t, recs)
	if !got[0].found {
		t.Errorf("exact-match TXT should be Found; got=%+v", got[0])
	}
	if got[1].found {
		t.Error("mismatched TXT must not be Found")
	}
	if got[1].actual == "" {
		t.Error("mismatch should still surface the actual value so operators can diff")
	}
}

func TestLookupVerifier_TLSA_Match_WithoutDNSSEC(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.setAD(false)
	s.add("_443._tcp.agent.example.com.", "TLSA",
		`_443._tcp.agent.example.com. 3600 IN TLSA 3 1 1 e31701de748c6339aa403571c2052d715d5fe83dbec9906611fbc430965c0133`)

	recs := []domain.ExpectedDNSRecord{{
		Name: "_443._tcp.agent.example.com", Type: domain.DNSRecordTLSA,
		Value:    "3 1 1 e31701de748c6339aa403571c2052d715d5fe83dbec9906611fbc430965c0133",
		Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if !got[0].found {
		t.Errorf("TLSA should match; got=%+v", got[0])
	}
	if got[0].dnssec {
		t.Error("DNSSECVerified must be false when resolver did not set AD bit")
	}
}

func TestLookupVerifier_TLSA_DNSSECFlagPropagates(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.setAD(true) // simulate a validating resolver
	s.add("_443._tcp.agent.example.com.", "TLSA",
		`_443._tcp.agent.example.com. 3600 IN TLSA 3 1 1 e31701de748c6339aa403571c2052d715d5fe83dbec9906611fbc430965c0133`)

	recs := []domain.ExpectedDNSRecord{{
		Name: "_443._tcp.agent.example.com", Type: domain.DNSRecordTLSA,
		Value:    "3 1 1 E31701DE748C6339AA403571C2052D715D5FE83DBEC9906611FBC430965C0133", // uppercase hex; normalizer must lowercase
		Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if !got[0].found {
		t.Errorf("TLSA should match regardless of hex casing; got=%+v", got[0])
	}
	if !got[0].dnssec {
		t.Error("DNSSECVerified must surface true when the response carried the AD bit")
	}
}

func TestLookupVerifier_HTTPSMatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	s.add("agent.example.com.", "HTTPS",
		`agent.example.com. 3600 IN HTTPS 1 . alpn="h2"`)

	// Our SVCB presentation formatter renders unquoted param values
	// ("alpn=h2"), matching the zone-file minimal form. Whitespace
	// differences vs the server's wire output get normalized before
	// comparison.
	recs := []domain.ExpectedDNSRecord{{
		Name: "agent.example.com", Type: domain.DNSRecordHTTPS,
		Value:    `1 . alpn=h2`,
		Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if !got[0].found {
		t.Errorf("HTTPS should match; got=%+v", got[0])
	}
}

func TestLookupVerifier_NXDOMAINSurfacedAsError(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	// No records added — server returns NXDOMAIN.
	recs := []domain.ExpectedDNSRecord{{
		Name: "missing.agent.example.com", Type: domain.DNSRecordTXT,
		Value: "doesnt-matter", Required: true,
	}}
	got := s.verifyAgainst(t, recs)
	if got[0].found {
		t.Error("NXDOMAIN must not be Found")
	}
	if got[0].errString == "" {
		t.Error("NXDOMAIN should surface a descriptive error")
	}
}

func TestLookupVerifier_UnknownTypeSurfacedAsError(t *testing.T) {
	t.Parallel()
	v := NewLookupVerifier(WithServer("127.0.0.1:1"), WithTimeout(50*time.Millisecond))
	rec := domain.ExpectedDNSRecord{
		Name: "agent.example.com", Type: domain.DNSRecordType("WEIRD"),
		Value: "v", Required: false,
	}
	got, err := v.VerifyRecords(context.Background(), "agent.example.com", []domain.ExpectedDNSRecord{rec})
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if got.Results[0].Found {
		t.Error("unknown type must not be marked Found")
	}
	if got.Results[0].Error == "" {
		t.Error("unknown type should surface a descriptive error")
	}
}

func TestLookupVerifier_NewHasDefaultTimeout(t *testing.T) {
	t.Parallel()
	v := NewLookupVerifier()
	if v.timeout != 5*time.Second {
		t.Errorf("default timeout: got %v, want 5s", v.timeout)
	}
	if v.client == nil {
		t.Error("client must be initialized")
	}
}
