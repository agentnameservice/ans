package handler

// Direct tests for the small status-mapping helpers in dto.go.
// Pre-coverage phaseFromStatus + completedStepsFor + pendingStepsFor
// + mapCSRStatus all sat at 60% or under because the integration
// tests only run the happy-path enum values. Pinning every arm
// here lets a future spec-aligned status enum reorder safely.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// mustReq builds a minimal *http.Request for the schemeOf tests
// below. Local to this file to avoid clashing with helpers in other
// _test.go files in the same package.
func mustReq(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, target, nil)
}

func TestPhaseFromStatus_AllArms(t *testing.T) {
	cases := map[domain.RegistrationStatus]string{
		domain.StatusPendingValidation:       "DOMAIN_VALIDATION",
		domain.StatusPendingDNS:              "DNS_PROVISIONING",
		domain.StatusActive:                  "COMPLETED",
		domain.RegistrationStatus("UNKNOWN"): "INITIALIZATION",
	}
	for status, want := range cases {
		if got := phaseFromStatus(status); got != want {
			t.Errorf("phaseFromStatus(%q): got %q want %q", status, got, want)
		}
	}
}

func TestCompletedStepsFor_AllArms(t *testing.T) {
	cases := map[domain.RegistrationStatus][]string{
		domain.StatusPendingDNS: {"DOMAIN_VALIDATION"},
		domain.StatusActive:     {"DOMAIN_VALIDATION", "CERTIFICATE_ISSUANCE", "DNS_PROVISIONING"},
		// Default arm (any other status) returns nil.
		domain.StatusPendingValidation: nil,
	}
	for status, want := range cases {
		got := completedStepsFor(status)
		if len(got) != len(want) {
			t.Errorf("completedStepsFor(%q): got %v want %v", status, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("completedStepsFor(%q)[%d]: got %q want %q", status, i, got[i], want[i])
			}
		}
	}
}

func TestPendingStepsFor_AllArms(t *testing.T) {
	cases := map[domain.RegistrationStatus][]string{
		domain.StatusPendingValidation: {"DOMAIN_VALIDATION"},
		domain.StatusPendingDNS:        {"DNS_PROVISIONING"},
		domain.StatusActive:            nil, // default arm
	}
	for status, want := range cases {
		got := pendingStepsFor(status)
		if len(got) != len(want) {
			t.Errorf("pendingStepsFor(%q): got %v want %v", status, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("pendingStepsFor(%q)[%d]: got %q want %q", status, i, got[i], want[i])
			}
		}
	}
}

func TestMapCSRStatus_RejectedSynthesizesFailureReason(t *testing.T) {
	// REJECTED with empty RejectionReason → synthesized message.
	now := time.Now()
	c := &domain.AgentCSR{
		CSRID:               "csr-1",
		Type:                domain.CSRType("IDENTITY"),
		Status:              domain.CSRStatusRejected,
		SubmissionTimestamp: now.Add(-time.Hour),
		ProcessedTimestamp:  now,
		// RejectionReason intentionally empty.
	}
	got := mapCSRStatus(c)
	if got.FailureReason == nil {
		t.Fatal("expected FailureReason to be set on REJECTED CSR")
	}
	if *got.FailureReason == "" {
		t.Error("FailureReason should be a non-empty placeholder, got empty string")
	}
}

func TestMapCSRStatus_RejectedKeepsExplicitReason(t *testing.T) {
	now := time.Now()
	c := &domain.AgentCSR{
		CSRID:               "csr-1",
		Type:                domain.CSRType("IDENTITY"),
		Status:              domain.CSRStatusRejected,
		SubmissionTimestamp: now,
		ProcessedTimestamp:  now,
		RejectionReason:     "key too small",
	}
	got := mapCSRStatus(c)
	if got.FailureReason == nil || *got.FailureReason != "key too small" {
		t.Errorf("explicit RejectionReason lost: %+v", got.FailureReason)
	}
}

func TestMapCSRStatus_NonRejectedStateOmitsFailureReason(t *testing.T) {
	now := time.Now()
	c := &domain.AgentCSR{
		CSRID:               "csr-1",
		Type:                domain.CSRType("IDENTITY"),
		Status:              domain.CSRStatusSigned,
		SubmissionTimestamp: now.Add(-time.Hour),
		ProcessedTimestamp:  now,
	}
	got := mapCSRStatus(c)
	if got.FailureReason != nil {
		t.Errorf("FailureReason should be nil for non-rejected state, got %v", *got.FailureReason)
	}
}

func TestMapCSRStatus_NoProcessedTimestampUsesSubmittedForUpdated(t *testing.T) {
	// Pre-processing CSR: ProcessedTimestamp is zero → updatedAt
	// should equal submittedAt.
	now := time.Now()
	c := &domain.AgentCSR{
		CSRID:               "csr-1",
		Type:                domain.CSRType("IDENTITY"),
		Status:              domain.CSRStatusPending,
		SubmissionTimestamp: now,
	}
	got := mapCSRStatus(c)
	if got.SubmittedAt != got.UpdatedAt {
		t.Errorf("updatedAt should fall back to submittedAt when no processedTimestamp; got %q vs %q",
			got.UpdatedAt, got.SubmittedAt)
	}
}

// schemeOf has three arms (TLS, X-Forwarded-Proto, default). The
// integration tests only hit the "no TLS, no header" default. Cover
// the other two here.
func TestSchemeOf_XForwardedProtoTakesPrecedenceOverHTTP(t *testing.T) {
	// Construct a request via httptest without TLS but with the
	// header set — should yield the header value.
	req := mustReq(t, "GET", "https://example.com/x")
	req.TLS = nil
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := schemeOf(req); got != "https" {
		t.Errorf("schemeOf with X-Forwarded-Proto: got %q want https", got)
	}
}

func TestSchemeOf_DefaultsToHTTP(t *testing.T) {
	req := mustReq(t, "GET", "/x")
	req.TLS = nil
	if got := schemeOf(req); got != "http" {
		t.Errorf("schemeOf default: got %q want http", got)
	}
}

// rfc3339Zero is a shared helper between v1+v2 registration mappers.
// Pre-coverage it sat at 66.7% — only the non-zero branch was
// exercised. Pin both arms.
func TestRFC3339Zero_BothArms(t *testing.T) {
	if got := rfc3339Zero(time.Time{}); got != "" {
		t.Errorf("zero time should yield empty string; got %q", got)
	}
	in := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	got := rfc3339Zero(in)
	if got != "2026-04-17T12:00:00Z" {
		t.Errorf("non-zero time: got %q want 2026-04-17T12:00:00Z", got)
	}
}

// buildRegistrationChallenges short-circuits to nil for a registration
// whose ACMEChallenge is zero (the post-active-after-restore case).
// Pre-coverage only the populated branch was hit.
func TestBuildRegistrationChallenges_NoChallengeYieldsNil(t *testing.T) {
	reg := &domain.AgentRegistration{}
	if got := buildRegistrationChallenges(reg); got != nil {
		t.Errorf("zero ACMEChallenge should yield nil challenges; got %v", got)
	}
}

// extractCertInfo's empty-string short-circuit returns ok=false with
// a zero info struct. Pre-coverage only the populated branch was
// exercised through the cert-issuance integration tests.
func TestExtractCertInfo_EmptyPEM(t *testing.T) {
	info, ok := extractCertInfo("")
	if ok {
		t.Errorf("expected ok=false for empty PEM")
	}
	if info != (certInfo{}) {
		t.Errorf("expected zero-value certInfo for empty PEM; got %+v", info)
	}
}

// extractCertInfo's parse-error branch fires when the PEM is
// malformed.
func TestExtractCertInfo_GarbagePEM(t *testing.T) {
	_, ok := extractCertInfo("not a pem block")
	if ok {
		t.Errorf("expected ok=false for garbage PEM")
	}
}
