// Package challenge provides adapters for verifying domain-control
// challenge artifacts the domain owner has published. Verification
// only — ANS never publishes challenge artifacts on the owner's
// behalf.
package challenge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// maxChallengeBodyBytes bounds the response read. Key authorizations
// are ~130 bytes; anything past a few KiB is not a challenge artifact.
const maxChallengeBodyBytes = 8 * 1024

// errBlockedDialTarget is returned by the SSRF guard when a dial
// resolves to a non-public address. It is internal — callers see only
// "challenge not satisfied" — but distinct so the guard is testable.
var errBlockedDialTarget = errors.New("challenge: refusing to dial a non-public address")

// HTTPVerifier implements port.HTTPChallengeVerifier by fetching the
// challenge URL over plain HTTP and comparing the body to the
// expected content. Plain HTTP (port 80) is the RFC 8555 §8.3 shape —
// the agent cannot present a valid TLS cert for the FQDN yet, since
// obtaining one is the very thing being validated.
//
// The fetch target is the agent's own registrant-supplied FQDN, so
// the client is hardened against SSRF: it refuses HTTP redirects and
// refuses to connect to any non-public address (loopback,
// link-local — including the 169.254.169.254 cloud metadata
// endpoint — private, unique-local, multicast, or unspecified). The
// guard runs on every dial via the dialer Control hook, so it sees
// the post-DNS-resolution IP and defeats DNS-rebinding as well as
// redirect-based pivots.
type HTTPVerifier struct {
	client *http.Client
	// urlFor builds the fetch URL from (fqdn, path). The default is
	// "http://" + fqdn + path; tests substitute an httptest server.
	urlFor func(fqdn, path string) string
}

// HTTPVerifierOption configures the verifier at construction time.
type HTTPVerifierOption func(*HTTPVerifier)

// WithHTTPClient overrides the HTTP client (timeouts, transport).
// Intended for tests; production uses the SSRF-hardened default.
func WithHTTPClient(c *http.Client) HTTPVerifierOption {
	return func(v *HTTPVerifier) { v.client = c }
}

// WithURLBuilder overrides how the challenge URL is derived from the
// FQDN and path. Intended for tests pointing at an httptest server;
// production uses the RFC 8555 default.
func WithURLBuilder(f func(fqdn, path string) string) HTTPVerifierOption {
	return func(v *HTTPVerifier) { v.urlFor = f }
}

// NewHTTPVerifier constructs an HTTPVerifier with a conservative
// default timeout and the SSRF guard installed. Challenge fetches hit
// operator infrastructure that may be slow to come up; 10s matches
// typical ACME validator budgets.
func NewHTTPVerifier(opts ...HTTPVerifierOption) *HTTPVerifier {
	v := &HTTPVerifier{
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: refuseRedirects, Transport: guardedTransport()},
		urlFor: func(fqdn, path string) string { return "http://" + fqdn + path },
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// refuseRedirects is the http.Client CheckRedirect hook: HTTP-01 does
// not require following redirects (RFC 8555 §8.3), and following them
// would reopen the SSRF surface the dial guard closes (a public host
// 302-ing to an internal one). Returning an error stops the chain;
// http.Client surfaces it, the caller treats it as not-published.
func refuseRedirects(_ *http.Request, _ []*http.Request) error {
	return errors.New("challenge: refusing to follow redirect")
}

// guardedTransport returns an http.Transport whose dialer rejects any
// connection to a non-public address. The Control hook fires after
// DNS resolution with the concrete IP being dialed, so it guards the
// resolved target (defeating DNS rebinding) and every redirect/retry
// dial, not just the literal host in the URL.
func guardedTransport() *http.Transport {
	d := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("challenge: parse dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublicIP(ip) {
				return fmt.Errorf("%w: %s", errBlockedDialTarget, host)
			}
			return nil
		},
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// The stdlib default is always *http.Transport; fall back to a
		// fresh one if some test rewired it.
		base = &http.Transport{}
	}
	t := base.Clone()
	// Never proxy. ProxyFromEnvironment (inherited from
	// http.DefaultTransport) would route the fetch through an
	// HTTP(S)_PROXY whose own address the dial guard sees as public —
	// the proxy would then fetch the internal target on our behalf,
	// defeating the guard entirely. HTTP-01 validation must dial the
	// resolved FQDN directly, so the Control hook above governs the
	// real target.
	t.Proxy = nil
	t.DialContext = d.DialContext
	return t
}

// isPublicIP reports whether ip is a globally-routable unicast address
// safe to dial for challenge verification. It fails closed: anything it
// cannot positively classify as public is rejected.
//
// Beyond the stdlib predicates (loopback, link-local — which covers the
// 169.254.169.254 cloud-metadata endpoint — RFC 1918 private, ULA,
// unspecified, multicast) it rejects ranges those predicates miss:
//   - 100.64.0.0/10 — RFC 6598 carrier-grade NAT, widely reused for
//     cloud-internal addressing (AWS EKS pod networking, internal
//     load-balancer targets); net.IP.IsPrivate covers only RFC 1918.
//   - 192.0.0.0/24  — RFC 6890 IETF protocol assignments.
//   - 198.18.0.0/15 — RFC 2544 benchmarking.
//   - 2002::/16     — 6to4 and
//   - 64:ff9b::/96  — NAT64: both embed an IPv4 address a translating
//     egress path could pivot to an internal host, and neither is a
//     form a legitimate public challenge target resolves to.
//
// These guard against a registrant pointing the FQDN under validation
// at an internal address to coerce a server-side request into
// infrastructure the verifier must never reach. Ranges are matched by
// byte math rather than a parsed CIDR table to keep the guard free of
// package-level state.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 (CGNAT)
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return false
		case v4[0] == 198 && v4[1]&0xfe == 18: // 198.18.0.0/15
			return false
		}
		return true
	}
	// IPv6 that is not an IPv4-mapped form (those are normalized by
	// To4() above and caught by the stdlib predicates). Reject the 6to4
	// and NAT64 encapsulations outright.
	if v6 := ip.To16(); v6 != nil {
		switch {
		case v6[0] == 0x20 && v6[1] == 0x02: // 2002::/16 (6to4)
			return false
		case v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b: // 64:ff9b::/96 (NAT64)
			return false
		}
	}
	return true
}

// VerifyHTTPChallenge fetches the challenge URL and reports whether
// the body matches the expected content. Trailing whitespace is
// tolerated (RFC 8555 §8.3 lets validators accept a trailing
// newline); any other difference is a mismatch. Network errors,
// blocked-target/redirect refusals, and non-200 statuses report
// (false, nil) — an unreachable, non-public, or not-yet-configured
// host is indistinguishable from "not published", and the caller's
// gate treats all of them as the challenge not being satisfied yet.
func (v *HTTPVerifier) VerifyHTTPChallenge(ctx context.Context, fqdn, path, expectedContent string) (bool, error) {
	if fqdn == "" || path == "" || expectedContent == "" {
		return false, errors.New("challenge: fqdn, path, and expectedContent are required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.urlFor(fqdn, path), http.NoBody)
	if err != nil {
		return false, fmt.Errorf("challenge: build request: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		// Connection refused / DNS failure / timeout / blocked
		// non-public target / refused redirect: the artifact is not
		// retrievable, so control is not proven. Not a systemic
		// error — the owner simply hasn't published a reachable,
		// public artifact.
		return false, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBodyBytes))
	if err != nil {
		return false, nil
	}
	return strings.TrimRight(string(body), "\r\n \t") == expectedContent, nil
}
