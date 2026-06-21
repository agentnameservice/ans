// Package acmetest provides an in-process fake RFC 8555 server for
// exercising the ACME issuer adapter without network access. It
// covers exactly the endpoints the issuer drives — directory, nonce,
// new-account, new-order, authorization, challenge accept, order
// poll, finalize, and certificate download — and exposes knobs to
// simulate slow validation, terminal failure, and pre-completed
// orders. JWS request bodies are decoded without signature
// verification: the code under test is the ACME client, never the
// server.
//
// Test-support only; production deployments point the issuer at a
// real directory URL (Let's Encrypt staging or production).
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// RFC 8555 status strings, mirrored locally so this package doesn't
// depend on x/crypto/acme.
const (
	statusPending = "pending"
	statusReady   = "ready"
	statusValid   = "valid"
	statusInvalid = "invalid"
)

// Server is the fake ACME provider. Construct with New, point the
// issuer at DirectoryURL(), and drive scenarios via the setters.
type Server struct {
	srv *httptest.Server

	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate

	mu          sync.Mutex
	orderStatus string
	// holdPending freezes the order in pending after a challenge is
	// accepted — simulates slow provider-side validation.
	holdPending bool
	// failValidation moves the order to invalid after accept.
	failValidation bool
	// failFinalize makes the finalize endpoint answer 500.
	failFinalize bool
	// unsupportedChallengesOnly makes authorizations offer only a
	// challenge type the adapter can't satisfy (tls-alpn-01), so
	// CreateOrder surfaces the no-supported-challenges error.
	unsupportedChallengesOnly bool
	accepted                  []string
	errs                      []error

	dnsToken  string
	httpToken string
}

// New starts the fake server with a fresh in-memory root CA. Callers
// must Close it (or register it with t.Cleanup).
func New() (*Server, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmetest Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	s := &Server{
		rootKey:     rootKey,
		rootCert:    rootCert,
		orderStatus: statusPending,
		dnsToken:    "dns-token-1",
		httpToken:   "http-token-1",
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s, nil
}

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// DirectoryURL is what the issuer's directory-url config points at.
func (s *Server) DirectoryURL() string { return s.url("/dir") }

// OrderURL returns the provider order URL the fake hands out — what
// CreateOrder relays as the order ref.
func (s *Server) OrderURL() string { return s.url("/order/1") }

// DNSToken returns the dns-01 challenge token the fake mints.
func (s *Server) DNSToken() string { return s.dnsToken }

// HTTPToken returns the http-01 challenge token the fake mints.
func (s *Server) HTTPToken() string { return s.httpToken }

// SetHoldPending freezes (or unfreezes) the order in pending after a
// challenge accept — provider-side validation that outlives the
// caller's finalize budget.
func (s *Server) SetHoldPending(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holdPending = v
}

// SetFailValidation makes the next accepted challenge move the order
// to invalid.
func (s *Server) SetFailValidation(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failValidation = v
}

// SetFailFinalize makes the finalize endpoint answer 500 — a
// provider-side outage mid-issuance.
func (s *Server) SetFailFinalize(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failFinalize = v
}

// SetOrderStatus force-sets the order state (e.g. "ready" to resume
// a held validation, "valid" to simulate an already-issued order).
func (s *Server) SetOrderStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orderStatus = status
}

// Accepted returns the challenge kinds ("dns", "http") the client
// answered — the assertion surface for the Verified contract.
func (s *Server) Accepted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.accepted...)
}

// Err returns the first protocol violation the fake observed (bad
// JWS, malformed CSR, unexpected path), or nil.
func (s *Server) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) == 0 {
		return nil
	}
	return s.errs[0]
}

func (s *Server) url(path string) string { return s.srv.URL + path }

func (s *Server) recordErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, err)
}

// jwsPayload extracts the base64url payload of a JWS request body
// without verifying the signature. Empty payload = POST-as-GET.
func (s *Server) jwsPayload(r *http.Request) []byte {
	var body struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.recordErr(fmt.Errorf("acmetest: decode jws: %w", err))
		return nil
	}
	if body.Payload == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Payload)
	if err != nil {
		s.recordErr(fmt.Errorf("acmetest: decode payload: %w", err))
		return nil
	}
	return raw
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Replay-Nonce", "nonce-"+time.Now().Format("150405.000000000"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) orderJSON() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := map[string]any{
		"status":         s.orderStatus,
		"expires":        time.Now().Add(time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": "agent.example.com"}},
		"authorizations": []string{s.url("/authz/1")},
		"finalize":       s.url("/finalize/1"),
	}
	if s.orderStatus == statusValid {
		o["certificate"] = s.url("/cert/1")
	}
	return o
}

// SetUnsupportedChallengesOnly makes authorizations offer only a
// challenge type the adapter cannot satisfy (tls-alpn-01).
func (s *Server) SetUnsupportedChallengesOnly(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unsupportedChallengesOnly = v
}

func (s *Server) authzJSON() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	authzStatus := statusPending
	if len(s.accepted) > 0 || s.orderStatus != statusPending {
		authzStatus = statusValid
	}
	challenges := []map[string]string{
		{"type": "dns-01", "url": s.url("/chal/dns"), "token": s.dnsToken, "status": statusPending},
		{"type": "http-01", "url": s.url("/chal/http"), "token": s.httpToken, "status": statusPending},
	}
	if s.unsupportedChallengesOnly {
		challenges = []map[string]string{
			{"type": "tls-alpn-01", "url": s.url("/chal/alpn"), "token": s.dnsToken, "status": statusPending},
		}
	}
	return map[string]any{
		"status":     authzStatus,
		"expires":    time.Now().Add(time.Hour).Format(time.RFC3339),
		"identifier": map[string]string{"type": "dns", "value": "agent.example.com"},
		"challenges": challenges,
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/dir":
		s.writeJSON(w, http.StatusOK, map[string]string{
			"newNonce":   s.url("/nonce"),
			"newAccount": s.url("/acct"),
			"newOrder":   s.url("/order"),
			"revokeCert": s.url("/revoke"),
			"keyChange":  s.url("/keychange"),
		})
	case r.URL.Path == "/nonce":
		w.Header().Set("Replay-Nonce", "nonce-head")
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/acct":
		w.Header().Set("Location", s.url("/acct/1"))
		s.writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
	case r.URL.Path == "/order":
		_ = s.jwsPayload(r)
		w.Header().Set("Location", s.OrderURL())
		s.writeJSON(w, http.StatusCreated, s.orderJSON())
	case r.URL.Path == "/order/1":
		w.Header().Set("Retry-After", "1")
		s.writeJSON(w, http.StatusOK, s.orderJSON())
	case r.URL.Path == "/authz/1":
		s.writeJSON(w, http.StatusOK, s.authzJSON())
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		s.mu.Lock()
		s.accepted = append(s.accepted, strings.TrimPrefix(r.URL.Path, "/chal/"))
		switch {
		case s.failValidation:
			s.orderStatus = statusInvalid
		case s.holdPending:
			// stay pending — validation "running"
		default:
			s.orderStatus = statusReady
		}
		s.mu.Unlock()
		s.writeJSON(w, http.StatusOK, map[string]string{"type": "dns-01", "status": "processing", "token": s.dnsToken})
	case r.URL.Path == "/finalize/1":
		s.handleFinalize(w, r)
	case r.URL.Path == "/cert/1":
		_ = s.jwsPayload(r)
		w.Header().Set("Replay-Nonce", "nonce-cert")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		chain, err := s.issueChain()
		if err != nil {
			s.recordErr(err)
			return
		}
		_, _ = w.Write(chain)
	default:
		s.recordErr(fmt.Errorf("acmetest: unexpected path %s", r.URL.Path))
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleFinalize validates the finalize JWS + CSR and flips the
// order to valid (or answers 500 when SetFailFinalize is armed).
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	failFinalize := s.failFinalize
	s.mu.Unlock()
	if failFinalize {
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"type": "urn:ietf:params:acme:error:serverInternal", "detail": "boom",
		})
		return
	}
	payload := s.jwsPayload(r)
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.recordErr(fmt.Errorf("acmetest: finalize payload: %w", err))
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.recordErr(fmt.Errorf("acmetest: csr decode: %w", err))
	}
	if _, err := x509.ParseCertificateRequest(csrDER); err != nil {
		s.recordErr(fmt.Errorf("acmetest: csr parse: %w", err))
	}
	s.mu.Lock()
	s.orderStatus = statusValid
	s.mu.Unlock()
	s.writeJSON(w, http.StatusOK, s.orderJSON())
}

// issueChain signs a leaf for the test FQDN with the fake root and
// returns leaf+root PEM.
func (s *Server) issueChain() ([]byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "agent.example.com"},
		DNSNames:     []string{"agent.example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.rootCert, leafKey.Public(), s.rootKey)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.rootCert.Raw})...)
	return out, nil
}
