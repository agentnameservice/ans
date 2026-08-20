package securefetch

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

// TestDialer_RejectsDisallowedPort pins WithRequirePort: a connection on
// any other port is refused before DNS, and a malformed address errors.
func TestDialer_RejectsDisallowedPort(t *testing.T) {
	d := NewDialer(WithRequirePort("443"))
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:8443"); err == nil {
		t.Fatal("non-443 should be rejected")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "malformed"); err == nil {
		t.Fatal("malformed address should be rejected")
	}
}

// TestDialer_BlocksLoopback drives the real dial path: the pinning
// dialer must reject a loopback-resolving host by address class.
func TestDialer_BlocksLoopback(t *testing.T) {
	d := NewDialer(WithRequirePort("443"))
	_, err := d.DialContext(context.Background(), "tcp", "localhost:443")
	if err == nil || !strings.Contains(err.Error(), "disallowed") {
		t.Fatalf("loopback should be rejected: %v", err)
	}
}

// TestDialer_NoRequirePortStillDenylists confirms that with no port
// restriction the egress denylist still rejects a loopback target.
func TestDialer_NoRequirePortStillDenylists(t *testing.T) {
	d := NewDialer()
	_, err := d.DialContext(context.Background(), "tcp", "localhost:8443")
	if err == nil || !strings.Contains(err.Error(), "disallowed") {
		t.Fatalf("loopback should be rejected regardless of port: %v", err)
	}
}

// TestDialer_AllowPrivateReachesLoopback proves the test-only escape
// hatch bypasses the class filter and reaches the real dial path.
func TestDialer_AllowPrivateReachesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if conn, aerr := ln.Accept(); aerr == nil {
			_ = conn.Close()
		}
	}()

	d := NewDialer(WithRequirePort("443"), WithAllowPrivateNetworks())
	conn, err := d.DialContext(context.Background(), "tcp", "localhost:443")
	if err == nil {
		_ = conn.Close()
	} else if strings.Contains(err.Error(), "disallowed") {
		t.Fatalf("allowPrivate must bypass the class filter: %v", err)
	}
}

func TestIsPublicUnicast(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // cloud metadata (link-local)
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"ff02::1", false},
		{"0.0.0.0", false},
		{"93.184.216.34", true},
		{"2606:2800:220:1::1", true},
	}
	for _, tc := range cases {
		if got := IsPublicUnicast(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsPublicUnicast(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	if d, err := RegistrableDomain("www.acme-corp.com"); err != nil || d != "acme-corp.com" {
		t.Fatalf("registrable domain = %q, %v", d, err)
	}
	if _, err := RegistrableDomain("localhost"); err == nil {
		t.Fatal("single-label host must have no registrable domain")
	}
}

func TestReadCappedBody(t *testing.T) {
	body, err := ReadCappedBody(bytes.NewReader([]byte("hello")), 1024)
	if err != nil || string(body) != "hello" {
		t.Fatalf("within cap: %q, %v", body, err)
	}
	if _, err := ReadCappedBody(bytes.NewReader(make([]byte, 4096)), 1024); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("over cap: want ErrBodyTooLarge, got %v", err)
	}
}

func TestNewClient_WiresRedirectPolicy(t *testing.T) {
	sentinel := errors.New("blocked")
	c := NewClient(NewDialer(), nil, func(*http.Request, []*http.Request) error { return sentinel })
	if c.Transport == nil || c.CheckRedirect == nil {
		t.Fatal("client missing transport or redirect policy")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, sentinel) {
		t.Fatalf("redirect policy not wired: %v", err)
	}
}
