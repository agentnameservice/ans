package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// LookupVerifier performs real DNS queries via miekg/dns so we can
// check every record type ANS uses (TXT, TLSA, HTTPS) and surface
// the DNSSEC authenticated-data bit on TLSA responses.
//
// By default queries go through the system resolver (reads
// /etc/resolv.conf via dns.ClientConfigFromFile). Override with
// WithServer("host:port") to target a specific nameserver — used by
// the local `ans-dns` dev server and by tests.
type LookupVerifier struct {
	// server is "host:port"; empty means "use the OS resolv.conf".
	server  string
	timeout time.Duration
	client  *dns.Client
}

// LookupOption configures a LookupVerifier.
type LookupOption func(*LookupVerifier)

// WithTimeout sets the per-query timeout (default 5s).
func WithTimeout(d time.Duration) LookupOption {
	return func(v *LookupVerifier) { v.timeout = d }
}

// WithServer targets a specific DNS server (e.g. "127.0.0.1:15353"
// for the local `ans-dns` dev server). Empty string restores the
// default behavior of reading /etc/resolv.conf.
func WithServer(addr string) LookupOption {
	return func(v *LookupVerifier) { v.server = addr }
}

// NewLookupVerifier returns a verifier backed by miekg/dns.
func NewLookupVerifier(opts ...LookupOption) *LookupVerifier {
	v := &LookupVerifier{
		timeout: 5 * time.Second,
		client:  new(dns.Client),
	}
	for _, opt := range opts {
		opt(v)
	}
	v.client.Timeout = v.timeout
	return v
}

// VerifyRecords runs one DNS query per expected record and reports
// the per-record result. TLSA queries set the AD bit on the outgoing
// message so a DNSSEC-validating resolver will signal validation via
// msg.AuthenticatedData on the response.
func (v *LookupVerifier) VerifyRecords(
	ctx context.Context,
	fqdn string,
	expected []domain.ExpectedDNSRecord,
) (*port.VerificationResult, error) {
	_ = fqdn // retained for future per-agent scoping; not needed for the lookup itself

	server, err := v.resolverAddress()
	if err != nil {
		return nil, err
	}

	results := make([]port.RecordVerification, len(expected))
	allRequired := true

	for i, rec := range expected {
		r := port.RecordVerification{Record: rec}
		lookupCtx, cancel := context.WithTimeout(ctx, v.timeout)
		switch rec.Type {
		case domain.DNSRecordTXT:
			r = v.verifyTXT(lookupCtx, server, rec)
		case domain.DNSRecordTLSA:
			r = v.verifyTLSA(lookupCtx, server, rec)
		case domain.DNSRecordHTTPS:
			r = v.verifyHTTPS(lookupCtx, server, rec)
		case domain.DNSRecordSVCB:
			r = v.verifySVCB(lookupCtx, server, rec)
		default:
			r.Error = fmt.Sprintf("unsupported record type: %s", rec.Type)
		}
		cancel()
		results[i] = r
		if rec.Required && !r.Found {
			allRequired = false
		}
	}
	return &port.VerificationResult{AllRequired: allRequired, Results: results}, nil
}

// resolverAddress returns the host:port of the nameserver to query.
// When WithServer set it explicitly, use that; otherwise read
// /etc/resolv.conf and take the first entry. Returns an error only
// if neither source provides an address.
func (v *LookupVerifier) resolverAddress() (string, error) {
	if v.server != "" {
		return v.server, nil
	}
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("dns: load resolv.conf: %w", err)
	}
	if len(cfg.Servers) == 0 {
		return "", errors.New("dns: no nameservers configured in /etc/resolv.conf")
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port), nil
}

// exchange issues a single DNS query through miekg/dns, requesting
// DNSSEC-validated answers where applicable via the AD bit.
func (v *LookupVerifier) exchange(ctx context.Context, server string, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	// AD bit asks a validating resolver to set the
	// authenticated-data flag on its reply if the answer validated
	// against the DNSSEC chain.
	m.AuthenticatedData = true
	// EDNS0 with DO=1 so the server includes signatures / signals
	// validation. SetEdns0 enables DO by default.
	m.SetEdns0(4096, true)
	resp, _, err := v.client.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (v *LookupVerifier) verifyTXT(ctx context.Context, server string, rec domain.ExpectedDNSRecord) port.RecordVerification {
	r := port.RecordVerification{Record: rec}
	resp, err := v.exchange(ctx, server, rec.Name, dns.TypeTXT)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if resp.Rcode != dns.RcodeSuccess {
		r.Error = fmt.Sprintf("rcode %s", dns.RcodeToString[resp.Rcode])
		return r
	}
	wantNorm := strings.TrimSpace(rec.Value)
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		joined := strings.TrimSpace(strings.Join(txt.Txt, ""))
		if r.Actual == "" {
			r.Actual = joined
		}
		if joined == wantNorm {
			r.Found = true
			r.Actual = joined
			return r
		}
	}
	return r
}

// verifyTLSA matches on the full record wire format ("usage selector
// mtype hex"). Captures the DNSSEC AuthenticatedData bit — surfacing
// to the TL attestation when true so verifiers downstream can trust
// the cert-binding without re-querying DNS themselves.
//
// DNSSECVerified is set from the response's AD bit regardless of
// whether the value matched. This is load-bearing for the service
// layer's post-verify rule: a DNSSEC-authenticated response whose
// TLSA value doesn't match the expected fingerprint is a hard fail
// (an attacker rewrote the record in a signed zone), so the service
// needs the AD signal on mismatches too.
func (v *LookupVerifier) verifyTLSA(ctx context.Context, server string, rec domain.ExpectedDNSRecord) port.RecordVerification {
	r := port.RecordVerification{Record: rec}
	resp, err := v.exchange(ctx, server, rec.Name, dns.TypeTLSA)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if resp.Rcode != dns.RcodeSuccess {
		r.Error = fmt.Sprintf("rcode %s", dns.RcodeToString[resp.Rcode])
		return r
	}
	r.DNSSECVerified = resp.AuthenticatedData
	wantNorm := normalizeTLSA(rec.Value)
	for _, rr := range resp.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		got := fmt.Sprintf("%d %d %d %s",
			tlsa.Usage, tlsa.Selector, tlsa.MatchingType, tlsa.Certificate)
		if r.Actual == "" {
			r.Actual = got
		}
		if normalizeTLSA(got) == wantNorm {
			r.Found = true
			r.Actual = got
			return r
		}
	}
	return r
}

// verifyHTTPS checks for an HTTPS-type record (RFC 9460). Matching
// compares the SvcPriority + TargetName + params text verbatim
// against the expected value after whitespace normalization.
//
// Captures the DNSSEC AuthenticatedData bit on the response, mirroring
// verifyTLSA and verifySVCB. The service-layer post-verify rule
// (lifecycle.go verifyDNSRecords) treats a DNSSEC-authenticated HTTPS
// record whose value disagrees with the expected one as a hard fail
// — same threat shape as TLSA: an attacker rewrote a record in a
// signed zone.
func (v *LookupVerifier) verifyHTTPS(ctx context.Context, server string, rec domain.ExpectedDNSRecord) port.RecordVerification {
	r := port.RecordVerification{Record: rec}
	resp, err := v.exchange(ctx, server, rec.Name, dns.TypeHTTPS)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if resp.Rcode != dns.RcodeSuccess {
		r.Error = fmt.Sprintf("rcode %s", dns.RcodeToString[resp.Rcode])
		return r
	}
	r.DNSSECVerified = resp.AuthenticatedData
	wantNorm := normalizeHTTPS(rec.Value)
	for _, rr := range resp.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		got := formatHTTPSValue(&https.SVCB)
		if r.Actual == "" {
			r.Actual = got
		}
		if normalizeHTTPS(got) == wantNorm {
			r.Found = true
			r.Actual = got
			return r
		}
	}
	return r
}

// formatHTTPSValue renders an HTTPS/SVCB record as "priority target key=val ..."
// matching the zone-file presentation format the RA's
// ComputeRequiredDNSRecords uses (e.g. "1 . alpn=h2").
func formatHTTPSValue(s *dns.SVCB) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d %s", s.Priority, s.Target)
	for _, p := range s.Value {
		fmt.Fprintf(&sb, " %s=%s", p.Key(), p.String())
	}
	return sb.String()
}

// verifySVCB checks for a Consolidated Approach SVCB record (RFC 9460)
// at the agent's bare FQDN. Multiple SVCB records can share one RRset
// name distinguished by alpn, and the Consolidated Approach explicitly
// designs for multi-family coexistence in a single record — sibling
// families can share one SVCB row, distinguished by their own
// SvcParamKeys. Verification therefore implements RFC 9460 §8
// unknown-key ignore semantics as a *subset* match: priority and
// target must equal the expected value exactly, every expected
// SvcParam must be present in the live record with an equal value,
// and additional SvcParams in the live record are tolerated.
//
// A strict-equality matcher would mark a multi-spec record not-found
// and (in a DNSSEC-signed zone) trip the SVCB_DNSSEC_MISMATCH hard
// fail in the lifecycle layer — defeating the entire point of the
// Consolidated Approach.
func (v *LookupVerifier) verifySVCB(ctx context.Context, server string, rec domain.ExpectedDNSRecord) port.RecordVerification {
	r := port.RecordVerification{Record: rec}
	resp, err := v.exchange(ctx, server, rec.Name, dns.TypeSVCB)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if resp.Rcode != dns.RcodeSuccess {
		r.Error = fmt.Sprintf("rcode %s", dns.RcodeToString[resp.Rcode])
		return r
	}
	r.DNSSECVerified = resp.AuthenticatedData

	expected, err := parseSVCBValue(rec.Value)
	if err != nil {
		r.Error = fmt.Sprintf("expected SVCB value: %v", err)
		return r
	}
	for _, rr := range resp.Answer {
		svcb, ok := rr.(*dns.SVCB)
		if !ok {
			continue
		}
		gotStr := formatHTTPSValue(svcb)
		if r.Actual == "" {
			r.Actual = gotStr
		}
		actual, err := parseSVCBValue(gotStr)
		if err != nil {
			// Skip records we can't parse — they'll surface as
			// not-found if no other answer matches.
			continue
		}
		if matchesSVCBSubset(expected, actual) {
			r.Found = true
			r.Actual = gotStr
			return r
		}
	}
	return r
}

// parsedSVCB is the structured form of an SVCB or HTTPS record's
// presentation value: priority, target, and a SvcParam map. Used for
// RFC 9460 §8-compliant subset matching in verifySVCB so that live
// records carrying extra SvcParams from coexisting specs aren't
// treated as mismatches.
type parsedSVCB struct {
	priority int
	target   string
	params   map[string]string
}

// parseSVCBValue parses the presentation form
// "<priority> <target> [k=v] [k=v] ..." that formatHTTPSValue emits
// (and that ComputeRequiredDNSRecords stores in
// ExpectedDNSRecord.Value). Whitespace inside SvcParam values is not
// supported because neither side emits it.
func parseSVCBValue(s string) (parsedSVCB, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return parsedSVCB{}, fmt.Errorf("svcb: too few fields in %q", s)
	}
	priority, err := strconv.Atoi(fields[0])
	if err != nil {
		return parsedSVCB{}, fmt.Errorf("svcb: priority %q: %w", fields[0], err)
	}
	out := parsedSVCB{
		priority: priority,
		target:   fields[1],
		params:   make(map[string]string, len(fields)-2),
	}
	for _, f := range fields[2:] {
		eq := strings.IndexByte(f, '=')
		if eq < 0 {
			// Valueless SvcParamKey (e.g. `no-default-alpn`); store
			// with empty value so an expected entry can still match.
			out.params[f] = ""
			continue
		}
		out.params[f[:eq]] = f[eq+1:]
	}
	return out, nil
}

// matchesSVCBSubset reports whether `actual` carries all SvcParams
// in `expected` (with equal values), tolerating any additional
// SvcParams in `actual`. Priority and target must match exactly.
//
// This is the verifier-side embodiment of RFC 9460 §8 unknown-key
// ignore semantics: the RA only verifies the SvcParams it committed
// to write; SvcParams from other agentic specs sharing the same
// SVCB row pass through unexamined.
func matchesSVCBSubset(expected, actual parsedSVCB) bool {
	if expected.priority != actual.priority || expected.target != actual.target {
		return false
	}
	for k, want := range expected.params {
		got, ok := actual.params[k]
		if !ok || got != want {
			return false
		}
	}
	return true
}

// normalizeTLSA collapses whitespace and lowercases the hex so
// "3 1 1 abcd..." matches "3  1  1 ABCD...".
func normalizeTLSA(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// normalizeHTTPS collapses whitespace for comparison. The SVCB
// param ordering is canonical via miekg/dns's Marshal, so field
// order isn't an issue for correctly-formed records.
func normalizeHTTPS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
