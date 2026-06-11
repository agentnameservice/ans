package leiverifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// b64 is the unpadded base64url encoding the noop wire shape uses.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// noopFixture mints an Ed25519 keypair and the matching noop
// presentation cesr + subject AID for the public key.
func noopFixture(t *testing.T, lei string) (ed25519.PrivateKey, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid := b64(pub)
	raw, err := json.Marshal(noopPresentation{PublicKey: aid, LEI: lei})
	if err != nil {
		t.Fatal(err)
	}
	return priv, aid, b64(raw)
}

func TestNoopPresentAndVerify(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()
	priv, aid, cesr := noopFixture(t, "5493001KJTIIGC8Y1R17")

	// Present recovers the AID + echoes the LEI + always AUTHORIZED.
	res, err := n.Present(ctx, cesr)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.SubjectAID != aid || res.LEI != "5493001KJTIIGC8Y1R17" || res.Status != "AUTHORIZED" {
		t.Fatalf("present result: %+v", res)
	}

	// Authorization authorizes a well-formed AID, asserts no LEI binding.
	auth, err := n.Authorization(ctx, aid)
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	if !auth.Authorized || auth.LEI != "" {
		t.Fatalf("authorization: %+v", auth)
	}

	// VerifySignature: a real Ed25519 signature over the signing input.
	const signingInput = "the-served-signing-input"
	sig := ed25519.Sign(priv, []byte(signingInput))
	ok, err := n.VerifySignature(ctx, aid, signingInput, b64(sig))
	if err != nil || !ok {
		t.Fatalf("verify good sig: ok=%v err=%v", ok, err)
	}
	// Tampered payload does not verify.
	if ok, _ := n.VerifySignature(ctx, aid, "other-input", b64(sig)); ok {
		t.Fatal("tampered payload should not verify")
	}
}

func TestNoopPresentFailures(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()
	_, validAID, _ := noopFixture(t, "X")

	noLEI, _ := json.Marshal(noopPresentation{PublicKey: validAID})
	badPub, _ := json.Marshal(noopPresentation{PublicKey: "not-base64url-key", LEI: "X"})

	cases := []struct {
		name string
		cesr string
	}{
		{"not base64url", "!!!not-base64!!!"},
		{"not a json object", b64([]byte("not json"))},
		{"bad public key", b64(badPub)},
		{"missing lei", b64(noLEI)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := n.Present(ctx, tc.cesr); !isCode(err, "LEI_PRESENTATION_INVALID") {
				t.Fatalf("want LEI_PRESENTATION_INVALID, got %v", err)
			}
		})
	}

	// A malformed AID to Authorization is an error (not a silent allow).
	if _, err := n.Authorization(ctx, "bogus-aid"); err == nil {
		t.Fatal("malformed AID should error")
	}

	// VerifySignature treats malformed AID / signature as a non-verifying
	// false, never an I/O error.
	if ok, err := n.VerifySignature(ctx, "bogus-aid", "in", b64([]byte("sig"))); ok || err != nil {
		t.Fatalf("bad aid: ok=%v err=%v", ok, err)
	}
	if ok, err := n.VerifySignature(ctx, validAID, "in", "!!!"); ok || err != nil {
		t.Fatalf("bad sig encoding: ok=%v err=%v", ok, err)
	}
	if ok, err := n.VerifySignature(ctx, validAID, "in", b64([]byte("too-short"))); ok || err != nil {
		t.Fatalf("wrong-length sig: ok=%v err=%v", ok, err)
	}
}

// vleiServer is a programmable stand-in for the vlei-verifier service.
type vleiServer struct {
	presentStatus int
	presentBody   string
	authStatus    int
	authBody      string
	verifyStatus  int
}

func (s *vleiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/presentations/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(s.presentStatus)
		_, _ = w.Write([]byte(s.presentBody))
	})
	mux.HandleFunc("/authorizations/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(s.authStatus)
		_, _ = w.Write([]byte(s.authBody))
	})
	mux.HandleFunc("/signature/verify", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(s.verifyStatus)
	})
	return mux
}

// validCESR is a minimal full-chain export: a leading ACDC frame whose
// self-addressing `d` is the presented credential SAID.
const validCESR = `{"v":"ACDC10JSON00011c_","d":"ECredSAID123","i":"EHolderAID","s":"ESchema","a":{"LEI":"5493001KJTIIGC8Y1R17"}}-CESR-attachments`

func newVerifierFor(t *testing.T, s *vleiServer) *Verifier {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return NewVerifier(srv.URL+"/", WithHTTPClient(srv.Client()), WithTimeout(2*time.Second), WithMaxBodyBytes(1<<16))
}

func TestVerifierPresentHappy(t *testing.T) {
	s := &vleiServer{
		presentStatus: http.StatusAccepted,
		presentBody:   `{"aid":"EHolderAID","said":"ECredSAID123"}`,
		authStatus:    http.StatusOK,
		authBody:      `{"aid":"EHolderAID","lei":"5493001KJTIIGC8Y1R17","role":"OOR"}`,
	}
	v := newVerifierFor(t, s)
	res, err := v.Present(context.Background(), validCESR)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.SubjectAID != "EHolderAID" || res.LEI != "5493001KJTIIGC8Y1R17" || res.Status != "AUTHORIZED" {
		t.Fatalf("present result: %+v", res)
	}
}

func TestVerifierPresentPendingAuthorization(t *testing.T) {
	// Presentation accepted but authorization still processing → PENDING.
	s := &vleiServer{
		presentStatus: http.StatusOK,
		presentBody:   `{"aid":"EHolderAID","said":"ECredSAID123"}`,
		authStatus:    http.StatusNotFound,
	}
	v := newVerifierFor(t, s)
	res, err := v.Present(context.Background(), validCESR)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.Status != "PENDING" || res.SubjectAID != "EHolderAID" {
		t.Fatalf("present result: %+v", res)
	}
}

func TestVerifierPresentFailures(t *testing.T) {
	t.Run("no ACDC frame", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{})
		if _, err := v.Present(context.Background(), "no acdc here"); !isCode(err, "LEI_PRESENTATION_INVALID") {
			t.Fatalf("want LEI_PRESENTATION_INVALID, got %v", err)
		}
	})
	t.Run("verifier rejects 4xx", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{presentStatus: http.StatusBadRequest})
		if _, err := v.Present(context.Background(), validCESR); !isCode(err, "LEI_PRESENTATION_INVALID") {
			t.Fatalf("want LEI_PRESENTATION_INVALID, got %v", err)
		}
	})
	t.Run("path-injecting SAID rejected before dial", func(t *testing.T) {
		// A leaf SAID carrying path/query characters must be rejected by the
		// qb64 guard — never interpolated into the request path.
		v := newVerifierFor(t, &vleiServer{presentStatus: http.StatusOK, presentBody: `{"aid":"EAID"}`})
		injecting := `{"v":"ACDC10JSON_","d":"../authorizations/EVIL?x=1"}`
		if _, err := v.Present(context.Background(), injecting); !isCode(err, "LEI_PRESENTATION_INVALID") {
			t.Fatalf("want LEI_PRESENTATION_INVALID, got %v", err)
		}
	})
	t.Run("verifier 5xx unavailable", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{presentStatus: http.StatusInternalServerError})
		if _, err := v.Present(context.Background(), validCESR); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
	t.Run("empty aid unavailable", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{presentStatus: http.StatusOK, presentBody: `{"said":"x"}`})
		if _, err := v.Present(context.Background(), validCESR); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
}

func TestVerifierAuthorization(t *testing.T) {
	ctx := context.Background()
	t.Run("authorized", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{authStatus: http.StatusOK, authBody: `{"lei":"L1"}`})
		auth, err := v.Authorization(ctx, "EAID")
		if err != nil || !auth.Authorized || auth.LEI != "L1" {
			t.Fatalf("auth=%+v err=%v", auth, err)
		}
	})
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		v := newVerifierFor(t, &vleiServer{authStatus: code})
		auth, err := v.Authorization(ctx, "EAID")
		if err != nil || auth.Authorized {
			t.Fatalf("status %d: auth=%+v err=%v", code, auth, err)
		}
	}
	t.Run("5xx unavailable", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{authStatus: http.StatusBadGateway})
		if _, err := v.Authorization(ctx, "EAID"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
	t.Run("non-qb64 AID rejected before dial", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{authStatus: http.StatusOK, authBody: `{"lei":"L1"}`})
		if _, err := v.Authorization(ctx, "../signature/verify"); !isCode(err, "LEI_SUBJECT_AID_INVALID") {
			t.Fatalf("want LEI_SUBJECT_AID_INVALID, got %v", err)
		}
	})
}

func TestVerifierVerifySignature(t *testing.T) {
	ctx := context.Background()
	t.Run("verifies", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{verifyStatus: http.StatusAccepted})
		ok, err := v.VerifySignature(ctx, "EAID", "input", "0Bsig")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
	// 401: bad signature; 400: malformed input; 404: AID unknown to the
	// verifier's KEL — all non-verifying signatures, never outages.
	for _, code := range []int{http.StatusUnauthorized, http.StatusBadRequest, http.StatusNotFound} {
		v := newVerifierFor(t, &vleiServer{verifyStatus: code})
		ok, err := v.VerifySignature(ctx, "EAID", "input", "0Bsig")
		if err != nil || ok {
			t.Fatalf("status %d: ok=%v err=%v", code, ok, err)
		}
	}
	t.Run("5xx unavailable", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{verifyStatus: http.StatusInternalServerError})
		if _, err := v.VerifySignature(ctx, "EAID", "input", "0Bsig"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
}

func TestVerifierUnreachable(t *testing.T) {
	// A base URL pointing nowhere → the client.Do error path → unavailable.
	v := NewVerifier("http://127.0.0.1:1", WithTimeout(500*time.Millisecond))
	if _, err := v.Authorization(context.Background(), "EAID"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
		t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
	}
}

func TestVerifierMalformedSuccessBodyFailsClosed(t *testing.T) {
	// A 200 carrying malformed JSON must surface as LEI_VERIFIER_UNAVAILABLE
	// instead of silently leaving out zero-valued — otherwise an authorized
	// response with junk JSON would degrade to the noop waiver (auth.LEI == "")
	// and the service's AID↔LEI binding check would be skipped.
	t.Run("present", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{presentStatus: http.StatusOK, presentBody: `{not-json`})
		if _, err := v.Present(context.Background(), validCESR); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
	t.Run("authorize", func(t *testing.T) {
		v := newVerifierFor(t, &vleiServer{authStatus: http.StatusOK, authBody: `{not-json`})
		if _, err := v.Authorization(context.Background(), "EAID"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
			t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
		}
	})
}

func TestVerifierBodyCapExceeded(t *testing.T) {
	// A response larger than the configured cap is treated as a protocol
	// failure (unavailable), never decoded — the response-size control.
	s := &vleiServer{authStatus: http.StatusOK, authBody: `{"lei":"a-body-far-larger-than-the-cap"}`}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	v := NewVerifier(srv.URL, WithHTTPClient(srv.Client()), WithMaxBodyBytes(8))
	if _, err := v.Authorization(context.Background(), "EAID"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
		t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
	}
}

func TestPresentedCredentialSAID(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"single credential", validCESR, "ECredSAID123"},
		{"no marker", "plain text", ""},
		{"escaped strings before d", `{"v":"ACDC10JSON_","note":"a \"quoted\" }brace","d":"EReal"}`, "EReal"},
		{"unterminated object", `{"v":"ACDC10JSON_","d":"x"`, ""},
		{"marker but no d, then a real one", `{"v":"ACDC10JSON_","x":1}{"v":"ACDC10JSON_","d":"ESecond"}`, "ESecond"},
		// Full-chain exports: the leaf is the credential no other
		// credential's edge `n` references — independent of frame order.
		// KERIA emits issuer-first (leaf last); we must not pick the first.
		{"chain leaf serialized last",
			`{"v":"ACDC10JSON_","d":"EQVI","a":{"LEI":"L"}}` +
				`{"v":"ACDC10JSON_","d":"ELE","e":{"d":"Eedge1","qvi":{"n":"EQVI","s":"S"}}}` +
				`{"v":"ACDC10JSON_","d":"EECR","e":{"d":"Eedge2","le":{"n":"ELE","s":"S"}}}`,
			"EECR"},
		{"chain leaf serialized first",
			`{"v":"ACDC10JSON_","d":"EECR","e":{"d":"Eedge2","le":{"n":"ELE","s":"S"}}}` +
				`{"v":"ACDC10JSON_","d":"ELE","e":{"d":"Eedge1","qvi":{"n":"EQVI","s":"S"}}}` +
				`{"v":"ACDC10JSON_","d":"EQVI","a":{"LEI":"L"}}`,
			"EECR"},
		// An edge group may be an ARRAY of edges (multi-source), and a
		// non-string `n` is ignored — both edge-walk branches exercised.
		{"edge group as array",
			`{"v":"ACDC10JSON_","d":"EROOT","a":{"LEI":"L"}}` +
				`{"v":"ACDC10JSON_","d":"ELEAF","e":{"d":"Eb","grp":[{"n":"EROOT","s":"S"},{"n":123}]}}`,
			"ELEAF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := presentedCredentialSAID(tc.in); got != tc.want {
				t.Fatalf("presentedCredentialSAID = %q, want %q", got, tc.want)
			}
		})
	}
}

func isCode(err error, code string) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Code == code
}
