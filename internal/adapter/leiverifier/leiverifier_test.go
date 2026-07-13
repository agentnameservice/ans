package leiverifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/domain"
)

// leafACDC is a minimal single-credential CESR export whose leaf carries
// the subject AID (a.i) and LEI (a.LEI) the noop pins and echoes — the
// same shape the real verifier receives.
const leafACDC = `{"v":"ACDC10JSON00011c_","d":"ECredSAID123","i":"EIssuerAID","s":"ESchema","a":{"i":"EHolderAID","LEI":"5493001KJTIIGC8Y1R17"}}`

func TestNoopPresent(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()

	// Present pins the leaf credential's subject AID, echoes its LEI, and
	// always reports AUTHORIZED (the live binding is waived).
	res, err := n.Present(ctx, leafACDC)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.SubjectAID != "EHolderAID" || res.LEI != "5493001KJTIIGC8Y1R17" || res.Status != "AUTHORIZED" {
		t.Fatalf("present result: %+v", res)
	}
}

func TestNoopPresentChainPinsLeafSubject(t *testing.T) {
	// Full-chain export: the noop pins the LEAF credential's subject AID
	// (the ECR), not an intermediate's — the same leaf selection the real
	// verifier uses, independent of frame order.
	ctx := context.Background()
	n := NewNoop()
	chain := `{"v":"ACDC10JSON_","d":"EQVI","a":{"i":"EQviSub","LEI":"L"}}` +
		`{"v":"ACDC10JSON_","d":"ELE","e":{"d":"Eedge1","qvi":{"n":"EQVI","s":"S"}},"a":{"i":"ELeSub","LEI":"L"}}` +
		`{"v":"ACDC10JSON_","d":"EECR","e":{"d":"Eedge2","le":{"n":"ELE","s":"S"}},"a":{"i":"EEcrSub","LEI":"875500ELOZEL05BVXV37"}}`
	res, err := n.Present(ctx, chain)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.SubjectAID != "EEcrSub" || res.LEI != "875500ELOZEL05BVXV37" {
		t.Fatalf("present result: %+v", res)
	}
}

func TestNoopPresentIgnoresKEL(t *testing.T) {
	// A real export interleaves KERI KEL events (icp/ixn) with ACDC frames;
	// the scan keys on the ACDC version marker, so KEL frames are ignored
	// and the leaf credential's subject AID is still pinned.
	ctx := context.Background()
	n := NewNoop()
	withKEL := `{"v":"KERI10JSON0001b7_","t":"icp","d":"EIncept","i":"EIncept","k":["DKey"]}` + leafACDC
	res, err := n.Present(ctx, withKEL)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if res.SubjectAID != "EHolderAID" {
		t.Fatalf("want subject AID EHolderAID, got %q", res.SubjectAID)
	}
}

func TestNoopPresentFailures(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()
	cases := []struct {
		name string
		cesr string
	}{
		{"no ACDC frame", "no acdc credential here"},
		{"leaf without subject AID", `{"v":"ACDC10JSON_","d":"ECred","a":{"LEI":"L"}}`},
		{"leaf with non-qb64 subject AID", `{"v":"ACDC10JSON_","d":"ECred","a":{"i":"../evil","LEI":"L"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := n.Present(ctx, tc.cesr); !isCode(err, "LEI_PRESENTATION_INVALID") {
				t.Fatalf("want LEI_PRESENTATION_INVALID, got %v", err)
			}
		})
	}
}

func TestNoopAuthorization(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()
	// A well-formed AID is authorized with NO live LEI binding asserted.
	auth, err := n.Authorization(ctx, "EHolderAID")
	if err != nil || !auth.Authorized || auth.LEI != "" {
		t.Fatalf("auth=%+v err=%v", auth, err)
	}
	// A non-qb64 AID is a validation error (mirrors the real verifier guard).
	if _, err := n.Authorization(ctx, "../signature/verify"); !isCode(err, "LEI_SUBJECT_AID_INVALID") {
		t.Fatalf("want LEI_SUBJECT_AID_INVALID, got %v", err)
	}
}

func TestNoopVerifySignature(t *testing.T) {
	ctx := context.Background()
	n := NewNoop()
	// Structural accept: well-formed qb64 AID + signature → true.
	if ok, err := n.VerifySignature(ctx, "EHolderAID", "signing-input", "0BsomeQb64Signature"); err != nil || !ok {
		t.Fatalf("structural accept: ok=%v err=%v", ok, err)
	}
	// A malformed AID or signature is a non-verifying false, never an error.
	cases := []struct{ name, aid, sig string }{
		{"bad aid", "../evil", "0Bsig"},
		{"bad sig", "EHolderAID", "!!!not-qb64!!!"},
		{"empty sig", "EHolderAID", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := n.VerifySignature(ctx, tc.aid, "in", tc.sig); ok || err != nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

type recordedRequest struct {
	method      string
	path        string
	contentType string
	body        string
}

// vleiServer is a programmable stand-in for the vlei-verifier service.
type vleiServer struct {
	presentStatus int
	presentBody   string
	authStatus    int
	authBody      string
	verifyStatus  int

	mu       sync.Mutex
	requests []recordedRequest // method, path, contentType, body
}

func (s *vleiServer) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, recordedRequest{
		method: r.Method, path: r.URL.Path,
		contentType: r.Header.Get("Content-Type"), body: string(body),
	})
}

func (s *vleiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/presentations/", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.WriteHeader(s.presentStatus)
		_, _ = w.Write([]byte(s.presentBody))
	})
	mux.HandleFunc("/authorizations/", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.WriteHeader(s.authStatus)
		_, _ = w.Write([]byte(s.authBody))
	})
	mux.HandleFunc("/signature/verify", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
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

// TestVerifierRequestShapes asserts the OUTBOUND contract — what the
// adapter sends, pins the path template, the content type, request-body fields
func TestVerifierRequestShapes(t *testing.T) {
	s := &vleiServer{
		presentStatus: http.StatusAccepted,
		presentBody:   `{"aid":"EHolderAID","said":"ECredSAID123"}`,
		authStatus:    http.StatusOK,
		authBody:      `{"lei":"5493001KJTIIGC8Y1R17"}`,
		verifyStatus:  http.StatusAccepted,
	}
	v := newVerifierFor(t, s)

	// Present → PUT /presentations/ECredSAID123 (leaf SAID from validCESR),
	// then GET /authorizations/EHolderAID (subject AID from the response).
	if _, err := v.Present(context.Background(), validCESR); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// VerifySignature → POST /signature/verify.
	if _, err := v.VerifySignature(context.Background(), "EHolderAID", "the-signing-input", "0BtheSignature"); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	if len(s.requests) != 3 {
		t.Fatalf("recorded %d requests, want 3: %+v", len(s.requests), s.requests)
	}
	present, auth, verify := s.requests[0], s.requests[1], s.requests[2]

	// PUT /presentations/{said}, application/json+cesr, CESR body verbatim.
	if present.method != http.MethodPut || present.path != "/presentations/ECredSAID123" {
		t.Errorf("present line = %s %s, want PUT /presentations/ECredSAID123", present.method, present.path)
	}
	if present.contentType != "application/json+cesr" {
		t.Errorf("present content-type = %q, want application/json+cesr", present.contentType)
	}
	if present.body != validCESR {
		t.Errorf("present body = %q, want the CESR export verbatim", present.body)
	}

	// GET /authorizations/{aid}, no body.
	if auth.method != http.MethodGet || auth.path != "/authorizations/EHolderAID" {
		t.Errorf("authorize line = %s %s, want GET /authorizations/EHolderAID", auth.method, auth.path)
	}

	// POST /signature/verify, application/json, exactly the three
	// snake_case tags bound to the right values. Decoding into a map keys
	// on the wire tags, so a struct-tag typo (signerAid, nonPrefixedDigest,
	// …) leaves the expected key absent and fails here.
	if verify.method != http.MethodPost || verify.path != "/signature/verify" {
		t.Errorf("verify line = %s %s, want POST /signature/verify", verify.method, verify.path)
	}
	if verify.contentType != "application/json" {
		t.Errorf("verify content-type = %q, want application/json", verify.contentType)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(verify.body), &got); err != nil {
		t.Fatalf("verify body is not JSON: %v (%q)", err, verify.body)
	}
	want := map[string]any{
		"signer_aid":          "EHolderAID",
		"signature":           "0BtheSignature",
		"non_prefixed_digest": "the-signing-input",
	}
	for k, wv := range want {
		if got[k] != wv {
			t.Errorf("verify body[%q] = %v, want %v", k, got[k], wv)
		}
	}
	if len(got) != len(want) {
		t.Errorf("verify body has %d fields, want exactly %d: %q", len(got), len(want), verify.body)
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
	// A 200 carrying no LEI (empty body or {}) must fail closed: an empty
	// LEI reads downstream as the noop waiver of the AID↔LEI binding, so
	// returning {Authorized:true, LEI:""} would silently degrade the
	// production verifier to noop semantics. Mirror the empty-AID guard.
	for _, body := range []string{"", "{}", `{"lei":""}`} {
		t.Run("200 without LEI unavailable", func(t *testing.T) {
			v := newVerifierFor(t, &vleiServer{authStatus: http.StatusOK, authBody: body})
			if _, err := v.Authorization(ctx, "EAID"); !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
				t.Fatalf("body %q: want LEI_VERIFIER_UNAVAILABLE, got %v", body, err)
			}
		})
	}
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
		// Insignificant JSON whitespace around `{`, the `v` key, and the
		// colon must not defeat the frame scan (pretty-printed export).
		{"whitespace around version member", "{ \"v\" :\t\"ACDC10JSON_\", \"d\": \"EWS\" }", "EWS"},
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

// TestCollectEdgeNodesDepthBound pins the recursion guard: a shallow `n`
// is collected, one nested past maxEdgeDepth (64) is ignored, and the
// walk terminates on adversarial deep nesting instead of overflowing.
func TestCollectEdgeNodesDepthBound(t *testing.T) {
	raw := json.RawMessage(`{"n":"ESHALLOW","deep":` +
		strings.Repeat(`{"x":`, 100) + `{"n":"EDEEP"}` + strings.Repeat(`}`, 100) + `}`)
	seen := map[string]struct{}{}
	collectEdgeNodes(raw, seen)
	if _, ok := seen["ESHALLOW"]; !ok {
		t.Fatal("shallow edge node not collected")
	}
	if _, ok := seen["EDEEP"]; ok {
		t.Fatal("edge node past maxEdgeDepth must be ignored")
	}
}

// TestVerifierLogsOperationalFailure pins the coarse-wire / detailed-log
// split (the did:web resolver's WithLogger precedent): an operational
// verifier failure surfaces the deliberately coarse LEI_VERIFIER_UNAVAILABLE
// wire error, which never names the configured host, while the diagnosable
// category — operation and HTTP status — goes only to the server-side log.
func TestVerifierLogsOperationalFailure(t *testing.T) {
	var logbuf bytes.Buffer
	srv := httptest.NewServer((&vleiServer{authStatus: http.StatusBadGateway}).handler())
	t.Cleanup(srv.Close)
	v := NewVerifier(srv.URL, WithHTTPClient(srv.Client()), WithLogger(zerolog.New(&logbuf)))

	_, err := v.Authorization(context.Background(), "EAID")
	if !isCode(err, "LEI_VERIFIER_UNAVAILABLE") {
		t.Fatalf("want LEI_VERIFIER_UNAVAILABLE, got %v", err)
	}
	// The wire error never echoes the configured host (no topology leak).
	if strings.Contains(err.Error(), "127.") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("wire error leaked the verifier host: %v", err)
	}
	// The diagnosable category reaches only the log.
	out := logbuf.String()
	if !strings.Contains(out, "vlei verifier call failed") ||
		!strings.Contains(out, `"op":"authorize"`) ||
		!strings.Contains(out, `"status":502`) {
		t.Fatalf("log did not record the failure category: %q", out)
	}
}

func isCode(err error, code string) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Code == code
}
