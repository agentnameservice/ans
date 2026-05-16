package did

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// fixture and httptest helpers --------------------------------------

const sampleJWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

type docFixture struct {
	id                 string
	verificationMethod []map[string]interface{}
	assertionMethod    []interface{}
	authentication     []interface{}
}

func (f docFixture) marshal(t *testing.T) []byte {
	t.Helper()
	out := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       f.id,
	}
	if len(f.verificationMethod) > 0 {
		out["verificationMethod"] = f.verificationMethod
	}
	if len(f.assertionMethod) > 0 {
		out["assertionMethod"] = f.assertionMethod
	}
	if len(f.authentication) > 0 {
		out["authentication"] = f.authentication
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// resolver tests -----------------------------------------------------

func mustClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestParseDIDWeb_Canonical(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantDomain  string
		wantPath    []string
		wantErr     bool
		wantErrCode string
	}{
		{
			name:       "domain only",
			input:      "did:web:agent.example.com",
			wantDomain: "agent.example.com",
			wantPath:   []string{},
		},
		{
			name:       "lowercases domain",
			input:      "did:web:Agent.Example.COM",
			wantDomain: "agent.example.com",
			wantPath:   []string{},
		},
		{
			name:       "with path components",
			input:      "did:web:agent.example.com:agents:billing",
			wantDomain: "agent.example.com",
			wantPath:   []string{"agents", "billing"},
		},
		{
			name:        "missing prefix",
			input:       "agent.example.com",
			wantErr:     true,
			wantErrCode: "DID_BAD_FORMAT",
		},
		{
			name:        "wrong method",
			input:       "did:plc:abc",
			wantErr:     true,
			wantErrCode: "DID_BAD_FORMAT",
		},
		{
			name:        "empty body",
			input:       "did:web:",
			wantErr:     true,
			wantErrCode: "DID_BAD_FORMAT",
		},
		{
			name:        "consecutive colons",
			input:       "did:web:agent.example.com::billing",
			wantErr:     true,
			wantErrCode: "DID_BAD_FORMAT",
		},
		{
			name:        "explicit port (percent-encoded colon) not supported",
			input:       "did:web:agent.example.com%3A8443",
			wantErr:     true,
			wantErrCode: "DID_PORT_NOT_SUPPORTED",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p, err := parseDIDWeb(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var dErr *domain.Error
				if !errors.As(err, &dErr) {
					t.Fatalf("error is not *domain.Error: %T", err)
				}
				if dErr.Code != c.wantErrCode {
					t.Errorf("code = %q, want %q", dErr.Code, c.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d != c.wantDomain {
				t.Errorf("domain = %q, want %q", d, c.wantDomain)
			}
			if !equalSlices(p, c.wantPath) {
				t.Errorf("path = %v, want %v", p, c.wantPath)
			}
		})
	}
}

func TestBuildResolutionURL(t *testing.T) {
	cases := []struct {
		name string
		dom  string
		path []string
		want string
	}{
		{
			name: "well-known path when no path components",
			dom:  "agent.example.com",
			want: "https://agent.example.com/.well-known/did.json",
		},
		{
			name: "path-based when components present",
			dom:  "agent.example.com",
			path: []string{"agents", "billing"},
			want: "https://agent.example.com/agents/billing/did.json",
		},
		{
			name: "URL-escapes path components",
			dom:  "agent.example.com",
			path: []string{"a b", "c"},
			want: "https://agent.example.com/a%20b/c/did.json",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildResolutionURL(c.dom, c.path)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestSelectVerificationMethodJWK_AssertionMethodWins(t *testing.T) {
	doc := &didDocument{
		ID: "did:web:agent.example.com",
		VerificationMethod: []verificationMethod{
			{
				ID:           "did:web:agent.example.com#auth-only",
				Type:         "Ed25519VerificationKey2020",
				PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AUTH"}`),
			},
			{
				ID:           "did:web:agent.example.com#assertion",
				Type:         "Ed25519VerificationKey2020",
				PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"ASSERT"}`),
			},
		},
		AssertionMethod: []json.RawMessage{json.RawMessage(`"#assertion"`)},
		Authentication:  []json.RawMessage{json.RawMessage(`"#auth-only"`)},
	}
	jwk, err := selectVerificationMethodJWK(doc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(jwk), `"x":"ASSERT"`) {
		t.Errorf("expected assertionMethod's key, got: %s", jwk)
	}
}

func TestSelectVerificationMethodJWK_FallsBackToAuthentication(t *testing.T) {
	doc := &didDocument{
		ID: "did:web:agent.example.com",
		VerificationMethod: []verificationMethod{
			{
				ID:           "did:web:agent.example.com#auth",
				Type:         "Ed25519VerificationKey2020",
				PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AUTH"}`),
			},
		},
		Authentication: []json.RawMessage{json.RawMessage(`"#auth"`)},
	}
	jwk, err := selectVerificationMethodJWK(doc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(jwk), `"x":"AUTH"`) {
		t.Errorf("expected authentication key, got: %s", jwk)
	}
}

func TestSelectVerificationMethodJWK_PicksMostRecent(t *testing.T) {
	doc := &didDocument{
		ID: "did:web:agent.example.com",
		VerificationMethod: []verificationMethod{
			{
				ID:           "did:web:agent.example.com#k-old",
				PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"OLD"}`),
				Updated:      "2026-01-01T00:00:00Z",
			},
			{
				ID:           "did:web:agent.example.com#k-new",
				PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"NEW"}`),
				Updated:      "2026-05-01T00:00:00Z",
			},
		},
		AssertionMethod: []json.RawMessage{
			json.RawMessage(`"#k-old"`),
			json.RawMessage(`"#k-new"`),
		},
	}
	jwk, err := selectVerificationMethodJWK(doc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(jwk), `"x":"NEW"`) {
		t.Errorf("expected newest key, got: %s", jwk)
	}
}

func TestSelectVerificationMethodJWK_EmbeddedObject(t *testing.T) {
	embedded := `{"id":"did:web:agent.example.com#k-1","type":"Ed25519VerificationKey2020","controller":"did:web:agent.example.com","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"EMBED"}}`
	doc := &didDocument{
		ID:              "did:web:agent.example.com",
		AssertionMethod: []json.RawMessage{json.RawMessage(embedded)},
	}
	jwk, err := selectVerificationMethodJWK(doc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(jwk), `"x":"EMBED"`) {
		t.Errorf("expected embedded key, got: %s", jwk)
	}
}

func TestVerificationMethodToJWK_UnsupportedShapes(t *testing.T) {
	cases := []struct {
		name     string
		vm       verificationMethod
		wantCode string
	}{
		{
			name:     "multibase not implemented",
			vm:       verificationMethod{ID: "k-mb", PublicKeyMultib: "z6Mk..."},
			wantCode: "DID_KEY_MULTIBASE_NOT_IMPLEMENTED",
		},
		{
			name:     "pem not implemented",
			vm:       verificationMethod{ID: "k-pem", PublicKeyPem: "-----BEGIN..."},
			wantCode: "DID_KEY_PEM_NOT_IMPLEMENTED",
		},
		{
			name:     "no key at all",
			vm:       verificationMethod{ID: "k-empty"},
			wantCode: "DID_KEY_MISSING",
		},
		{
			name:     "malformed JWK",
			vm:       verificationMethod{ID: "k-bad", PublicKeyJwk: json.RawMessage(`{not json}`)},
			wantCode: "DID_KEY_BAD_JWK",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := verificationMethodToJWK(c.vm)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) || dErr.Code != c.wantCode {
				t.Errorf("expected code %q, got %v", c.wantCode, err)
			}
		})
	}
}

func TestSameEffectiveDomain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"agent.example.com", "other.example.com", true},
		{"agent.example.com", "evil.example.org", false},
		{"agent.example.com:443", "other.example.com:8080", true},
		{"localhost", "localhost", true},
	}
	for _, c := range cases {
		got := sameEffectiveDomain(c.a, c.b)
		if got != c.want {
			t.Errorf("sameEffectiveDomain(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestWeb_Resolve_HappyPath(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	doc := docFixture{
		id: "did:web:agent.example.com",
		verificationMethod: []map[string]interface{}{
			{
				"id":           "did:web:agent.example.com#k-1",
				"type":         "Ed25519VerificationKey2020",
				"controller":   "did:web:agent.example.com",
				"publicKeyJwk": json.RawMessage(sampleJWK),
			},
		},
		assertionMethod: []interface{}{"#k-1"},
	}.marshal(t)

	// httptest server stand-in for the agent's HTTPS endpoint.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			t.Errorf("path = %q, want /.well-known/did.json", r.URL.Path)
		}
		accept := r.Header.Get("Accept")
		if !strings.Contains(accept, "application/did+json") {
			t.Errorf("Accept header missing did+json, got %q", accept)
		}
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(doc)
	}))
	defer server.Close()

	resolver := NewWeb().WithClock(mustClock(fixed)).WithHTTPClient(server.Client())

	// Override the http.Client transport to route the resolver's
	// https://agent.example.com URL to the httptest server.
	resolver.client = newRoutingClient(server)

	claim, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeDID {
		t.Errorf("AnchorType = %q, want did", claim.AnchorType)
	}
	if claim.ResolvedID != "did:web:agent.example.com" {
		t.Errorf("ResolvedID = %q", claim.ResolvedID)
	}
	if !claim.IssuedAt.Equal(fixed) {
		t.Errorf("IssuedAt = %v, want %v", claim.IssuedAt, fixed)
	}
	if claim.MetadataURL != "https://agent.example.com/.well-known/did.json" {
		t.Errorf("MetadataURL = %q", claim.MetadataURL)
	}
	if !strings.Contains(string(claim.PublicKeyJWK), `"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"`) {
		t.Errorf("unexpected JWK: %s", claim.PublicKeyJWK)
	}
}

func TestWeb_Resolve_DIDDocumentIDMismatch(t *testing.T) {
	doc := docFixture{
		id: "did:web:other.example.com", // wrong ID
		verificationMethod: []map[string]interface{}{
			{
				"id":           "did:web:other.example.com#k-1",
				"type":         "Ed25519VerificationKey2020",
				"publicKeyJwk": json.RawMessage(sampleJWK),
			},
		},
		assertionMethod: []interface{}{"#k-1"},
	}.marshal(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(doc)
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_DOCUMENT_ID_MISMATCH, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_DOCUMENT_ID_MISMATCH" {
		t.Errorf("expected DID_DOCUMENT_ID_MISMATCH, got %v", err)
	}
}

func TestWeb_Resolve_NotFound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_RESOLUTION_FAILED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_RESOLUTION_FAILED" {
		t.Errorf("expected DID_RESOLUTION_FAILED, got %v", err)
	}
}

func TestWeb_Resolve_BadContentType(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>"))
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_BAD_CONTENT_TYPE, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_BAD_CONTENT_TYPE" {
		t.Errorf("expected DID_BAD_CONTENT_TYPE, got %v", err)
	}
}

func TestWeb_SupportedProfiles(t *testing.T) {
	got := NewWeb().SupportedProfiles()
	if len(got) != 1 || got[0] != WebProfileID {
		t.Errorf("SupportedProfiles = %v", got)
	}
}

func TestWeb_Resolve_BadJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write([]byte(`{not json}`))
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_DOCUMENT_PARSE, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_DOCUMENT_PARSE" {
		t.Errorf("expected DID_DOCUMENT_PARSE, got %v", err)
	}
}

func TestWeb_Resolve_MissingID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write([]byte(`{"@context":"https://www.w3.org/ns/did/v1"}`))
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_DOCUMENT_PARSE, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_DOCUMENT_PARSE" {
		t.Errorf("expected DID_DOCUMENT_PARSE, got %v", err)
	}
}

func TestWeb_Resolve_PathComponents(t *testing.T) {
	doc := docFixture{
		id: "did:web:agent.example.com:agents:billing",
		verificationMethod: []map[string]interface{}{
			{
				"id":           "did:web:agent.example.com:agents:billing#k-1",
				"type":         "Ed25519VerificationKey2020",
				"publicKeyJwk": json.RawMessage(sampleJWK),
			},
		},
		assertionMethod: []interface{}{"#k-1"},
	}.marshal(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/billing/did.json" {
			t.Errorf("path = %q, want /agents/billing/did.json", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(doc)
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	claim, err := resolver.Resolve(context.Background(), "did:web:agent.example.com:agents:billing")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if claim.ResolvedID != "did:web:agent.example.com:agents:billing" {
		t.Errorf("ResolvedID = %q", claim.ResolvedID)
	}
	if claim.MetadataURL != "https://agent.example.com/agents/billing/did.json" {
		t.Errorf("MetadataURL = %q", claim.MetadataURL)
	}
}

func TestWeb_Resolve_NoVerificationMethod(t *testing.T) {
	doc := docFixture{
		id: "did:web:agent.example.com",
		// No verificationMethod, no assertionMethod, no authentication.
	}.marshal(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(doc)
	}))
	defer server.Close()

	resolver := NewWeb()
	resolver.client = newRoutingClient(server)

	_, err := resolver.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_NO_VERIFICATION_METHOD, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_NO_VERIFICATION_METHOD" {
		t.Errorf("expected DID_NO_VERIFICATION_METHOD, got %v", err)
	}
}

func TestWebRedirectPolicy_TooManyRedirects(t *testing.T) {
	// Build 5 prior requests; the 6th hop trips the limit.
	via := make([]*http.Request, 5)
	for i := range via {
		req, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/x", nil)
		via[i] = req
	}
	req, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/y", nil)
	if err := webRedirectPolicy(req, via); err == nil {
		t.Error("expected too-many-redirects error")
	}
}

func TestWebRedirectPolicy_CrossDomainRejected(t *testing.T) {
	original, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/x", nil)
	via := []*http.Request{original}
	cross, _ := http.NewRequest(http.MethodGet, "https://evil.example.org/x", nil)
	if err := webRedirectPolicy(cross, via); err == nil {
		t.Error("expected cross-domain redirect error")
	}
}

func TestWebRedirectPolicy_SameSiteAllowed(t *testing.T) {
	original, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/x", nil)
	via := []*http.Request{original}
	same, _ := http.NewRequest(http.MethodGet, "https://www.example.com/x", nil)
	if err := webRedirectPolicy(same, via); err != nil {
		t.Errorf("expected same-domain redirect to pass, got %v", err)
	}
}

func TestWeb_Resolve_BadFormatPropagates(t *testing.T) {
	resolver := NewWeb()
	_, err := resolver.Resolve(context.Background(), "did:plc:abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_BAD_FORMAT" {
		t.Errorf("expected DID_BAD_FORMAT, got %v", err)
	}
}

// equalSlices avoids importing reflect for one comparison.
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
