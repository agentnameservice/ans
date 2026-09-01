package service

// Integration cover across the seam that let a real defect through: the
// lookup adapter's per-record output feeding the attestation filter and its
// drop classification.
//
// Both sides were unit-tested and both were self-consistent, yet the pair
// disagreed. The adapter reported NXDOMAIN through Error, while every
// service-side fixture modelled ordinary absence as Error=="". So the
// filter's INFO/MISSING arm was covered by tests that no real lookup could
// produce, and the most common drop on real DNS — an operator declining
// DANE, which yields NXDOMAIN because the `_443._tcp` owner name is never
// created — landed on the WARN/LOOKUP_ERROR arm instead.
//
// Hand-written port.RecordVerification values cannot catch a disagreement
// of that kind, because they encode what the author believes the adapter
// does. These tests run the actual adapter against an actual nameserver and
// hand the real results to the real filter, so the two are pinned to each
// other rather than to an assumption.
//
// This is deliberately not driven through VerifyDNS. The drop summary is
// only ever logged, so asserting the INFO/WARN level would mean swapping
// the package-global zerolog logger from a parallel test. The cause is what
// selects the level (droppedForLookupError reads exactly it), so pinning
// the cause pins the level without the global mutation.

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	dnsadapter "github.com/agentnameservice/ans/internal/adapter/dns"
	"github.com/agentnameservice/ans/internal/domain"
)

// zone is a minimal authoritative nameserver over UDP. Names carrying
// records answer with them; names registered as existing but holding no
// record of the queried type answer NODATA; anything else is NXDOMAIN,
// matching what a real zone does for a label that was never created.
// The handler goroutine is running before the test populates the zone, so
// every map is guarded. Ordering the writes first is not enough on its own:
// without a synchronisation edge there is no happens-before relationship
// between the test goroutine's writes and the handler's reads, and the race
// detector is right to flag it.
type zone struct {
	addr     string
	mu       sync.RWMutex
	answers  map[string][]miekg.RR
	existing map[string]bool
	servfail map[string]bool
}

func newZone(t *testing.T) *zone {
	t.Helper()
	z := &zone{
		answers:  map[string][]miekg.RR{},
		existing: map[string]bool{},
		servfail: map[string]bool{},
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	z.addr = pc.LocalAddr().String()

	mux := miekg.NewServeMux()
	mux.HandleFunc(".", func(w miekg.ResponseWriter, req *miekg.Msg) {
		m := new(miekg.Msg)
		m.SetReply(req)
		m.Authoritative = true
		z.mu.RLock()
		if len(req.Question) > 0 {
			q := req.Question[0]
			name := strings.ToLower(q.Name)
			key := name + ":" + miekg.TypeToString[q.Qtype]
			switch {
			case z.servfail[key]:
				m.Rcode = miekg.RcodeServerFailure
			default:
				m.Answer = append(m.Answer, z.answers[key]...)
				if len(m.Answer) == 0 && !z.existing[name] {
					m.Rcode = miekg.RcodeNameError
				}
			}
		}
		z.mu.RUnlock()
		_ = w.WriteMsg(m)
	})

	srv := &miekg.Server{PacketConn: pc, Handler: mux}
	done := make(chan struct{})
	go func() {
		_ = srv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		<-done
	})
	time.Sleep(20 * time.Millisecond)
	return z
}

func (z *zone) add(rrString, typ string) {
	rr, err := miekg.NewRR(rrString)
	if err != nil {
		panic("zone.add: bad RR: " + err.Error())
	}
	key := strings.ToLower(rr.Header().Name) + ":" + typ
	z.mu.Lock()
	z.answers[key] = append(z.answers[key], rr)
	z.mu.Unlock()
}

func (z *zone) addName(name string) {
	z.mu.Lock()
	z.existing[strings.ToLower(miekg.Fqdn(name))] = true
	z.mu.Unlock()
}

func (z *zone) addServfail(name, typ string) {
	z.mu.Lock()
	z.servfail[strings.ToLower(miekg.Fqdn(name))+":"+typ] = true
	z.mu.Unlock()
}

// verify runs the real lookup adapter against this zone and feeds its
// per-record output straight into the real filter, returning what would be
// attested and the drop summary the seal path would log.
func (z *zone) verify(
	t *testing.T, recs []domain.ExpectedDNSRecord,
) ([]domain.ExpectedDNSRecord, []droppedRecord) {
	t.Helper()
	v := dnsadapter.NewLookupVerifier(
		dnsadapter.WithServer(z.addr), dnsadapter.WithTimeout(2*time.Second))
	res, err := v.VerifyRecords(context.Background(), "agent.example.com", recs)
	if err != nil {
		t.Fatalf("VerifyRecords: %v", err)
	}
	if len(res.Results) != len(recs) {
		t.Fatalf("adapter returned %d results for %d records", len(res.Results), len(recs))
	}
	return attestedDNSRecords(recs, res.Results)
}

// TestRealLookupOutputClassifiesAsMissing is the regression for the seam.
// An operator publishes the required discovery and badge records and
// declines the optional TLSA, which on real DNS means the `_443._tcp` label
// does not exist. The filter must drop that row, and it must report the
// drop as MISSING so it stays on the INFO arm — a routine operator choice,
// not an upstream fault that quietly narrowed a signed attestation.
func TestRealLookupOutputClassifiesAsMissing(t *testing.T) {
	t.Parallel()
	const (
		badgeName = "_ans-badge.agent.example.com"
		tlsaName  = "_443._tcp.agent.example.com"
		badgeVal  = "v=ans-badge1; id=abc"
	)
	z := newZone(t)
	z.add(`_ans-badge.agent.example.com. 3600 IN TXT "`+badgeVal+`"`, "TXT")

	recs := []domain.ExpectedDNSRecord{
		rec(badgeName, domain.DNSRecordTXT, badgeVal, true),
		rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 abcdef", false),
	}
	attested, dropped := z.verify(t, recs)

	if len(attested) != 1 || attested[0].Name != badgeName {
		t.Fatalf("only the published badge record may be attested; got %+v", attested)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected exactly one drop; got %+v", dropped)
	}
	got := dropped[0]
	if got.Name != tlsaName || got.Type != string(domain.DNSRecordTLSA) {
		t.Errorf("wrong record dropped: %+v", got)
	}
	if got.Cause != dropCauseMissing {
		t.Errorf("declining an optional record is MISSING, not %q — this is the classification that selects INFO over WARN", got.Cause)
	}
	if got.Error != "" {
		t.Errorf("absence must carry no resolver error; got %q", got.Error)
	}
	if droppedForLookupError(dropped) {
		t.Error("a skipped optional record must not escalate the drop log to WARN")
	}
}

// TestRealLookupOutputClassifiesNodataAsMissing covers the other absence
// shape end to end. The apex exists (it has other records) but carries no
// HTTPS RR, which is NODATA rather than NXDOMAIN — the CNAME-at-apex
// operator's position (RFC 1034 §3.6.2). It must classify identically.
func TestRealLookupOutputClassifiesNodataAsMissing(t *testing.T) {
	t.Parallel()
	const fqdn = "agent.example.com"
	z := newZone(t)
	z.addName(fqdn)

	recs := []domain.ExpectedDNSRecord{rec(fqdn, domain.DNSRecordHTTPS, "1 . alpn=h2", false)}
	attested, dropped := z.verify(t, recs)

	if len(attested) != 0 {
		t.Fatalf("an unpublished HTTPS RR must not be attested; got %+v", attested)
	}
	if len(dropped) != 1 || dropped[0].Cause != dropCauseMissing {
		t.Fatalf("NODATA is absence and must classify as MISSING; got %+v", dropped)
	}
	if droppedForLookupError(dropped) {
		t.Error("NODATA must not escalate to WARN")
	}
}

// TestRealLookupOutputClassifiesServfailAsLookupError is the other side of
// the split, and the reason the split exists. A SERVFAIL means the RA never
// learned whether the record was published, so the narrowing of a signed
// attestation was not the operator's decision and has to reach the logs at
// WARN with the resolver's own reason attached.
func TestRealLookupOutputClassifiesServfailAsLookupError(t *testing.T) {
	t.Parallel()
	const tlsaName = "_443._tcp.agent.example.com"
	z := newZone(t)
	z.addServfail(tlsaName, "TLSA")

	recs := []domain.ExpectedDNSRecord{rec(tlsaName, domain.DNSRecordTLSA, "3 0 1 abcdef", false)}
	attested, dropped := z.verify(t, recs)

	if len(attested) != 0 {
		t.Fatalf("a record whose lookup failed must not be attested; got %+v", attested)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected exactly one drop; got %+v", dropped)
	}
	got := dropped[0]
	if got.Cause != dropCauseLookupError {
		t.Errorf("SERVFAIL is a fault, not absence; got cause %q", got.Cause)
	}
	if !strings.Contains(got.Error, "SERVFAIL") {
		t.Errorf("the resolver's reason must survive into the log summary; got %q", got.Error)
	}
	if !droppedForLookupError(dropped) {
		t.Error("a resolver fault must escalate the drop log to WARN")
	}
}
