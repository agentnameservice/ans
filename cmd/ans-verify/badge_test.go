package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testAgentID  = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testBadgeTXT = "v=ans-badge1; version=v1; url=https://tl.example.com/v1/agents/" +
		testAgentID
)

// stubLookup returns a txtLookupFunc serving fixed answers, and records
// the name it was asked for.
func stubLookup(asked *string, txts []string, err error) txtLookupFunc {
	return func(_ context.Context, name string) ([]string, error) {
		if asked != nil {
			*asked = name
		}
		return txts, err
	}
}

func TestParseBadgeTXT_ReadsLogAndAgentFromURL(t *testing.T) {
	t.Parallel()
	b, err := parseBadgeTXT(testBadgeTXT)
	if err != nil {
		t.Fatalf("parseBadgeTXT: %v", err)
	}
	if b.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", b.AgentID, testAgentID)
	}
	if want := "https://tl.example.com"; b.TLBaseURL != want {
		t.Errorf("TLBaseURL = %q, want %q", b.TLBaseURL, want)
	}
	if b.Version != "v1" {
		t.Errorf("Version = %q, want %q", b.Version, "v1")
	}
}

func TestParseBadgeTXT_Tolerates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		txt       string
		wantBase  string
		wantAgent string
	}{
		{
			name:      "trailing slash on the url",
			txt:       "v=ans-badge1; url=https://tl.example.com/v1/agents/" + testAgentID + "/",
			wantBase:  "https://tl.example.com",
			wantAgent: testAgentID,
		},
		{
			name:      "no spaces after the separators",
			txt:       "v=ans-badge1;version=v2;url=https://tl.example.com/v1/agents/" + testAgentID,
			wantBase:  "https://tl.example.com",
			wantAgent: testAgentID,
		},
		{
			name:      "a log served under a path prefix",
			txt:       "v=ans-badge1; url=https://example.com/ans/tl/v1/agents/" + testAgentID,
			wantBase:  "https://example.com/ans/tl",
			wantAgent: testAgentID,
		},
		{
			name:      "http for a local deployment",
			txt:       "v=ans-badge1; url=http://localhost:18081/v1/agents/" + testAgentID,
			wantBase:  "http://localhost:18081",
			wantAgent: testAgentID,
		},
		{
			name:      "an uppercase key and version tag",
			txt:       "V=ANS-BADGE1; URL=https://tl.example.com/v1/agents/" + testAgentID,
			wantBase:  "https://tl.example.com",
			wantAgent: testAgentID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := parseBadgeTXT(tc.txt)
			if err != nil {
				t.Fatalf("parseBadgeTXT(%q): %v", tc.txt, err)
			}
			if b.TLBaseURL != tc.wantBase {
				t.Errorf("TLBaseURL = %q, want %q", b.TLBaseURL, tc.wantBase)
			}
			if b.AgentID != tc.wantAgent {
				t.Errorf("AgentID = %q, want %q", b.AgentID, tc.wantAgent)
			}
		})
	}
}

func TestParseBadgeTXT_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		txt     string
		wantErr string
	}{
		{
			name:    "some other TXT record at the same name",
			txt:     "v=spf1 -all",
			wantErr: "is not",
		},
		{
			name:    "a future badge version",
			txt:     "v=ans-badge2; url=https://tl.example.com/v1/agents/" + testAgentID,
			wantErr: "is not",
		},
		{
			name:    "no url",
			txt:     "v=ans-badge1; version=v1",
			wantErr: "no url=",
		},
		{
			// BadgeRecord falls back to the endpoint URL when the
			// deployment configured no TL base URL. That names a
			// reachable agent, not a log, so there is nothing to verify.
			name:    "the endpoint-URL fallback shape",
			txt:     "v=ans-badge1; url=https://agent.example.com",
			wantErr: "/v1/agents/<agentId> path",
		},
		{
			name:    "an agent id that is not a UUID",
			txt:     "v=ans-badge1; url=https://tl.example.com/v1/agents/../../etc/passwd",
			wantErr: "not a UUID agentId",
		},
		{
			name:    "an empty agent id",
			txt:     "v=ans-badge1; url=https://tl.example.com/v1/agents/",
			wantErr: "/v1/agents/<agentId> path",
		},
		{
			name:    "a non-http scheme",
			txt:     "v=ans-badge1; url=file:///v1/agents/" + testAgentID,
			wantErr: "is not http or https",
		},
		{
			name:    "no host",
			txt:     "v=ans-badge1; url=https:///v1/agents/" + testAgentID,
			wantErr: "no host",
		},
		{
			name:    "a query string",
			txt:     "v=ans-badge1; url=https://tl.example.com/v1/agents/" + testAgentID + "?as=admin",
			wantErr: "query, fragment or userinfo",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseBadgeTXT(tc.txt)
			if err == nil {
				t.Fatalf("parseBadgeTXT(%q) succeeded, want an error", tc.txt)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestResolveBadge_QueriesTheBadgeOwnerName(t *testing.T) {
	t.Parallel()
	var asked string
	b, err := resolveBadge(t.Context(),
		stubLookup(&asked, []string{testBadgeTXT}, nil), "agent.example.com.")
	if err != nil {
		t.Fatalf("resolveBadge: %v", err)
	}
	if want := "_ans-badge.agent.example.com"; asked != want {
		t.Errorf("queried %q, want %q", asked, want)
	}
	if b.Owner != "_ans-badge.agent.example.com" {
		t.Errorf("Owner = %q", b.Owner)
	}
	if b.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", b.AgentID, testAgentID)
	}
}

func TestResolveBadge_IgnoresUnrelatedTXTAtTheSameName(t *testing.T) {
	t.Parallel()
	b, err := resolveBadge(t.Context(), stubLookup(nil,
		[]string{"some-unrelated=value", testBadgeTXT}, nil), "agent.example.com")
	if err != nil {
		t.Fatalf("resolveBadge: %v", err)
	}
	if b.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", b.AgentID, testAgentID)
	}
}

func TestResolveBadge_AcceptsTheSameBadgePublishedTwice(t *testing.T) {
	t.Parallel()
	b, err := resolveBadge(t.Context(),
		stubLookup(nil, []string{testBadgeTXT, testBadgeTXT + "/"}, nil), "agent.example.com")
	if err != nil {
		t.Fatalf("resolveBadge: %v", err)
	}
	if b.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", b.AgentID, testAgentID)
	}
}

func TestResolveBadge_Failures(t *testing.T) {
	t.Parallel()
	otherAgent := "11111111-2222-3333-4444-555555555555"
	tests := []struct {
		name    string
		fqdn    string
		txts    []string
		err     error
		wantErr string
	}{
		{
			name:    "an empty FQDN",
			fqdn:    "  ",
			wantErr: "empty FQDN",
		},
		{
			name:    "a lookup failure",
			fqdn:    "agent.example.com",
			err:     errors.New("server misbehaving"),
			wantErr: "lookup TXT _ans-badge.agent.example.com",
		},
		{
			name:    "no records at the name",
			fqdn:    "agent.example.com",
			txts:    nil,
			wantErr: "no \"v=ans-badge1\" TXT record",
		},
		{
			name:    "records, but no badge among them",
			fqdn:    "agent.example.com",
			txts:    []string{"v=spf1 -all"},
			wantErr: "1 TXT record(s) present",
		},
		{
			name:    "a badge that does not parse",
			fqdn:    "agent.example.com",
			txts:    []string{"v=ans-badge1; url=https://tl.example.com/badge"},
			wantErr: "malformed badge record",
		},
		{
			name: "two badges naming different agents",
			fqdn: "agent.example.com",
			txts: []string{
				testBadgeTXT,
				"v=ans-badge1; url=https://tl.example.com/v1/agents/" + otherAgent,
			},
			wantErr: "ambiguous",
		},
		{
			name: "two badges naming different logs",
			fqdn: "agent.example.com",
			txts: []string{
				testBadgeTXT,
				"v=ans-badge1; url=https://other-tl.example.com/v1/agents/" + testAgentID,
			},
			wantErr: "ambiguous",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveBadge(t.Context(), stubLookup(nil, tc.txts, tc.err), tc.fqdn)
			if err == nil {
				t.Fatal("resolveBadge succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestBadgeStep_AdoptsTheBadgeLogWhenURLWasNotSet(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	agentID, baseURL := badgeStep(t.Context(), badgeStepInput{
		FQDN:          "agent.example.com",
		Timeout:       time.Second,
		ConfiguredURL: "http://localhost:18081",
		URLExplicit:   false,
		Lookup:        stubLookup(nil, []string{testBadgeTXT}, nil),
		Out:           &out,
	})
	if agentID != testAgentID {
		t.Errorf("agentID = %q, want %q", agentID, testAgentID)
	}
	if want := "https://tl.example.com"; baseURL != want {
		t.Errorf("baseURL = %q, want %q", baseURL, want)
	}
	if !strings.Contains(out.String(), testBadgeTXT) {
		t.Errorf("output does not quote the record it read: %q", out.String())
	}
}

// An explicit -url is the operator's trust configuration. The badge is
// published by the same party as the agent, so it does not get to move
// verification to a log of its choosing.
func TestBadgeStep_ExplicitURLWinsOverTheBadge(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	agentID, baseURL := badgeStep(t.Context(), badgeStepInput{
		FQDN:          "agent.example.com",
		Timeout:       time.Second,
		ConfiguredURL: "https://pinned-tl.example.org",
		URLExplicit:   true,
		Lookup:        stubLookup(nil, []string{testBadgeTXT}, nil),
		Out:           &out,
	})
	if agentID != testAgentID {
		t.Errorf("agentID = %q, want %q", agentID, testAgentID)
	}
	if want := "https://pinned-tl.example.org"; baseURL != want {
		t.Errorf("baseURL = %q, want %q", baseURL, want)
	}
	if !strings.Contains(out.String(), "https://tl.example.com") {
		t.Errorf("output does not report the log the badge named: %q", out.String())
	}
}

func TestBadgeStep_ExplicitURLMatchingTheBadge(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	_, baseURL := badgeStep(t.Context(), badgeStepInput{
		FQDN:          "agent.example.com",
		Timeout:       time.Second,
		ConfiguredURL: "https://tl.example.com/",
		URLExplicit:   true,
		Lookup:        stubLookup(nil, []string{testBadgeTXT}, nil),
		Out:           &out,
	})
	if want := "https://tl.example.com"; baseURL != want {
		t.Errorf("baseURL = %q, want %q", baseURL, want)
	}
}

// The -dns flag has to actually reach the resolver it names, which is
// how the local `ans-dns` dev server is verified against. Serve the
// badge from a throwaway server and read it back through newTXTLookup.
func TestNewTXTLookup_ReadsTheBadgeFromTheNamedResolver(t *testing.T) {
	t.Parallel()
	addr := serveBadgeZone(t, "_ans-badge.agent.example.com.", testBadgeTXT)

	b, err := resolveBadge(t.Context(),
		newTXTLookup(addr, 5*time.Second), "agent.example.com")
	if err != nil {
		t.Fatalf("resolveBadge via %s: %v", addr, err)
	}
	if b.AgentID != testAgentID {
		t.Errorf("AgentID = %q, want %q", b.AgentID, testAgentID)
	}
	if want := "https://tl.example.com"; b.TLBaseURL != want {
		t.Errorf("TLBaseURL = %q, want %q", b.TLBaseURL, want)
	}
}

// The Go resolver reports the server from the system configuration in
// its errors even when Dial sent the query elsewhere, so a failed -dns
// lookup must say which resolver was actually used.
func TestNewTXTLookup_NamesTheResolverInItsError(t *testing.T) {
	t.Parallel()
	// Nothing listens on port 1 of loopback.
	_, err := newTXTLookup("127.0.0.1:1", 2*time.Second)(
		t.Context(), "_ans-badge.agent.example.com")
	if err == nil {
		t.Fatal("lookup against a dead resolver succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "via 127.0.0.1:1") {
		t.Errorf("error = %q, want it to name the resolver that was queried", err)
	}
}

// serveBadgeZone starts a UDP nameserver answering a single TXT name
// and returns its host:port. It is shut down when the test ends.
func serveBadgeZone(t *testing.T, owner, txt string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(owner, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name: owner, Rrtype: dns.TypeTXT,
					Class: dns.ClassINET, Ttl: 60,
				},
				Txt: []string{txt},
			})
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestFlagWasSet(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("ans-verify", flag.ContinueOnError)
	fs.String("url", "http://localhost:18081", "")
	fs.String("fqdn", "", "")
	if err := fs.Parse([]string{"-fqdn", "agent.example.com"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if flagWasSet(fs, "url") {
		t.Error("url reported as set, but it holds its default")
	}
	if !flagWasSet(fs, "fqdn") {
		t.Error("fqdn reported as unset, but it was passed")
	}
}

func TestNormalizeResolverAddr(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"127.0.0.1:15353", "127.0.0.1:15353"},
		{"127.0.0.1", "127.0.0.1:53"},
		{"resolver.example.com", "resolver.example.com:53"},
		{"::1", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
	}
	for _, tc := range tests {
		if got := normalizeResolverAddr(tc.in); got != tc.want {
			t.Errorf("normalizeResolverAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSameBaseURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://tl.example.com", "https://tl.example.com/", true},
		{"https://TL.example.com", "https://tl.example.com", true},
		{"https://tl.example.com", "http://tl.example.com", false},
		{"https://tl.example.com", "https://other.example.com", false},
	}
	for _, tc := range tests {
		if got := sameBaseURL(tc.a, tc.b); got != tc.want {
			t.Errorf("sameBaseURL(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
