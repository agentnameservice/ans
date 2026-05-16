package did

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

// newRoutingClient returns an http.Client whose Transport routes
// every connection to the given httptest.Server, regardless of the
// URL host the request targets. The TLS config is taken from the
// httptest server so the resolver's standard chain validation
// passes against the test cert.
//
// This is the core test fixture for did:web: the resolver builds
// "https://agent.example.com/.well-known/did.json" but the actual
// TCP connection terminates at httptest's loopback listener.
func newRoutingClient(server *httptest.Server) *http.Client {
	srvURL, _ := url.Parse(server.URL)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, srvURL.Host)
			},
		},
		CheckRedirect: webRedirectPolicy,
	}
}
