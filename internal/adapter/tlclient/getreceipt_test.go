package tlclient_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/tlclient"
	"github.com/godaddy/ans/internal/tl/receipt"
)

func TestGetReceipt_HappyPath(t *testing.T) {
	t.Parallel()
	const agentID = "11111111-2222-3333-4444-555555555555"
	// Build a real COSE_Sign1 receipt over fixed event bytes so the
	// VDP + payload-hash arithmetic the client does is exercised
	// end-to-end against bytes that came out of the production
	// generator path.
	eventBytes := []byte(`{"agent":"demo","leaf":0}`)
	receiptBytes := mintReceipt(t, eventBytes, 5, 0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/"+agentID+"/receipt" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", receipt.MediaType)
		_, _ = w.Write(receiptBytes)
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "", 5*time.Second)
	body, proof, err := c.GetReceipt(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetReceipt: %v", err)
	}
	if !bytesEqual(body, receiptBytes) {
		t.Errorf("body != receiptBytes")
	}
	if proof.TreeSize != 5 || proof.LeafIndex != 0 {
		t.Errorf("proof tree_size=%d leaf_index=%d, want 5/0", proof.TreeSize, proof.LeafIndex)
	}
	if len(proof.LeafHash) != 32 {
		t.Errorf("leaf_hash len = %d, want 32", len(proof.LeafHash))
	}
	// LeafHash MUST equal SHA-256(0x00 || eventBytes) — pin the RFC
	// 6962 calculation against drift.
	want := sha256.Sum256(append([]byte{0x00}, eventBytes...))
	if !bytesEqual(proof.LeafHash, want[:]) {
		t.Errorf("leaf_hash mismatch")
	}
}

func TestGetReceipt_503LeafUncommitted(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Receipt Not Yet Available","status":503,"code":"TL_LEAF_UNCOMMITTED","detail":"x"}`))
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLLeafUncommitted) {
		t.Fatalf("err = %v, want ErrTLLeafUncommitted", err)
	}
}

func TestGetReceipt_503OtherCodeIsNotReachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"SOMETHING_ELSE"}`))
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable", err)
	}
}

func TestGetReceipt_503UnparsableBodyIsNotReachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable", err)
	}
}

func TestGetReceipt_404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLAgentNotFound) {
		t.Fatalf("err = %v, want ErrTLAgentNotFound", err)
	}
}

func TestGetReceipt_500(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable", err)
	}
}

func TestGetReceipt_4xxOtherIsNotReachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable", err)
	}
}

func TestGetReceipt_TransportError(t *testing.T) {
	t.Parallel()
	// Point the client at a server that's already shut down so
	// http.Do returns a connect error.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()
	c := tlclient.New(url, "", 100*time.Millisecond)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable", err)
	}
}

func TestGetReceipt_EmptyAgentID(t *testing.T) {
	t.Parallel()
	c := tlclient.New("http://localhost", "", time.Second)
	_, _, err := c.GetReceipt(context.Background(), "")
	if err == nil {
		t.Fatal("want error for empty agentID")
	}
}

func TestGetReceipt_EmptyResponseBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable for empty body", err)
	}
}

func TestGetReceipt_MalformedCOSE(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0xFF, 0xFF, 0xFF})
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "", 5*time.Second)
	_, _, err := c.GetReceipt(context.Background(), "any")
	if !errors.Is(err, tlclient.ErrTLNotReachable) {
		t.Fatalf("err = %v, want ErrTLNotReachable for bad CBOR", err)
	}
}

func TestGetReceipt_ForwardsBearerAuth(t *testing.T) {
	t.Parallel()
	eventBytes := []byte(`{"x":1}`)
	receiptBytes := mintReceipt(t, eventBytes, 1, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer auth-proxy-key" {
			t.Errorf("Authorization = %q, want Bearer auth-proxy-key", got)
		}
		_, _ = w.Write(receiptBytes)
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "auth-proxy-key", 5*time.Second)
	if _, _, err := c.GetReceipt(context.Background(), "any"); err != nil {
		t.Fatalf("GetReceipt: %v", err)
	}
}

// --- helpers ---

// mintReceipt builds a real SCITT receipt over eventBytes for tests.
// Reuses the production receipt.Generator so the bytes are
// byte-identical to what the TL would produce.
func mintReceipt(t *testing.T, eventBytes []byte, treeSize, leafIndex uint64) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	km := &localKM{priv: priv}
	gen, err := receipt.NewKeyManagerGenerator(context.Background(), km, "k", "tl-test")
	if err != nil {
		t.Fatalf("NewKeyManagerGenerator: %v", err)
	}
	// Single-leaf tree: no siblings, root hash IS the leaf hash.
	leafHash := receipt.ComputeLeafHash(eventBytes)
	rec, err := gen.GenerateReceipt(context.Background(), &receipt.InclusionProof{
		TreeSize:  treeSize,
		LeafIndex: leafIndex,
		Path:      [][]byte{},
		RootHash:  leafHash,
	}, eventBytes)
	if err != nil {
		t.Fatalf("GenerateReceipt: %v", err)
	}
	return rec
}

// localKM is a port.KeyManager that signs with an in-memory P-256
// key. Returns ASN.1 DER signatures as the real KM does.
type localKM struct{ priv *ecdsa.PrivateKey }

func (k *localKM) Sign(_ context.Context, _ string, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
func (k *localKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, nil
}
func (k *localKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return &k.priv.PublicKey, nil
}
func (k *localKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (k *localKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

func bytesEqual(a, b []byte) bool {
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
