// Package securefetch is the shared hardened-HTTP toolkit behind every
// registrant-steered outbound fetch in the RA: the did:web DID-document
// resolver and the web-bot-auth Signature-Agent directory resolver both
// build their client here so the SSRF defense is written and audited
// once, not duplicated per adapter.
//
// The fetch target is chosen by an untrusted party (any host a DID or a
// Signature-Agent URL names), so SSRF is a first-class control:
//
//  1. Egress IP denylist enforced at connect time, POST-DNS: RFC 1918,
//     loopback, link-local (which covers the cloud-metadata addresses),
//     ULA, multicast, and unspecified addresses are rejected at the
//     dialer — never by hostname-string inspection, which a rebind
//     defeats.
//  2. The resolved IP is pinned per host for the life of one Dialer, so
//     a DNS rebind between redirect hops (or TLS retries) cannot slip an
//     internal target past check 1.
//  3. Full WebPKI validation (chain + hostname) on every fetch — Go's
//     default TLS behavior, left fully enabled; TLS 1.2 floor.
//  4. Bounded: caller-set timeout, response-size cap (ReadCappedBody),
//     and a redirect policy the caller supplies (typically bounded and
//     pinned to the origin's registrable domain).
//
// The package is deliberately free of any domain dependency: it returns
// coarse, oracle-free errors and lets each adapter map them to its own
// wire codes.
package securefetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// Dialer resolves, filters, and pins target IPs for one fetch round.
//
// The pin map lives for the life of the Dialer (one per client per
// resolve call): the first connection to a host fixes its IP, so a
// rebind between the initial fetch and a later redirect hop cannot
// redirect a connection to a different (possibly internal) address.
// Every chosen IP passes the denylist AFTER resolution.
type Dialer struct {
	allowPrivate bool
	requirePort  string // when set, the dialer refuses any other port

	mu  sync.Mutex
	pin map[string]string // host → ip
}

// DialerOption customizes a Dialer.
type DialerOption func(*Dialer)

// WithAllowPrivateNetworks disables the egress IP denylist. FOR TESTS
// ONLY — it exists so the full real dial path is exercisable against a
// loopback TLS server. Never reachable from configuration.
func WithAllowPrivateNetworks() DialerOption {
	return func(d *Dialer) { d.allowPrivate = true }
}

// WithRequirePort pins the dialer to a single destination port; a
// connection to any other port is refused before DNS resolution. The
// did:web resolver sets "443" (the method has no way to express a
// port); the web-bot-auth resolver leaves it empty because a
// Signature-Agent URL may carry an explicit port.
func WithRequirePort(port string) DialerOption {
	return func(d *Dialer) { d.requirePort = port }
}

// NewDialer builds a hardened dialer.
func NewDialer(opts ...DialerOption) *Dialer {
	d := &Dialer{}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// DialContext dials addr, applying the port restriction (if any), the
// per-host pin, and the egress denylist.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("securefetch: malformed dial address")
	}
	if d.requirePort != "" && port != d.requirePort {
		return nil, errors.New("securefetch: refusing connection on a disallowed port")
	}

	d.mu.Lock()
	if d.pin == nil {
		d.pin = make(map[string]string)
	}
	pinnedIP, ok := d.pin[host]
	d.mu.Unlock()

	if !ok {
		pinnedIP, err = d.resolveAndPin(ctx, host)
		if err != nil {
			return nil, err
		}
	}

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, net.JoinHostPort(pinnedIP, port))
}

// resolveAndPin resolves the host, applies the egress denylist to every
// candidate address, and pins the first allowed IP. First writer wins —
// concurrent dials for one host converge on one pin.
func (d *Dialer) resolveAndPin(ctx context.Context, host string) (string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", errors.New("securefetch: host did not resolve")
	}
	chosen := ""
	for _, ip := range ips {
		if d.allowPrivate || IsPublicUnicast(ip.IP) {
			chosen = ip.IP.String()
			break
		}
	}
	if chosen == "" {
		return "", errors.New("securefetch: host resolves only to disallowed addresses")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, dup := d.pin[host]; dup {
		return existing, nil
	}
	d.pin[host] = chosen
	return chosen, nil
}

// IsPublicUnicast reports whether ip is a routable public unicast
// address. It rejects every class the egress denylist names: loopback,
// RFC 1918 / ULA private ranges, link-local (which contains the
// cloud-metadata addresses), multicast, and unspecified.
func IsPublicUnicast(ip net.IP) bool {
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return false
	default:
		return true
	}
}

// RegistrableDomain returns the eTLD+1 for a host. Single-label hosts
// (localhost, bare TLDs) error — they have no registrable domain, so a
// redirect policy anchored on one can never be satisfied.
func RegistrableDomain(host string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(strings.ToLower(host))
}

// NewClient assembles the hardened http.Client: the pinning dialer, full
// WebPKI validation (TLS 1.2 floor, caller-supplied root pool or system
// roots when nil), no idle keep-alives (each client serves one
// registrant-steered host for one round), and the caller's redirect
// policy.
func NewClient(d *Dialer, rootCAs *x509.CertPool, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	transport := &http.Transport{
		DialContext:       d.DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}
}

// ErrBodyTooLarge is returned by ReadCappedBody when the body exceeds
// the cap. Callers map it to their own wire code.
var ErrBodyTooLarge = errors.New("securefetch: response body exceeds the size limit")

// ReadCappedBody reads at most limit bytes from r, returning
// ErrBodyTooLarge if the source holds more. It reads limit+1 bytes so
// the overflow is detectable without trusting Content-Length.
func ReadCappedBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrBodyTooLarge
	}
	return body, nil
}
