package handler

// White-box tests for the small DNS-mismatch mappers that project
// service.DNSMismatch slices into handler DTOs. These are pure
// functions — worth a direct test rather than routing through the
// HTTP layer.

import (
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

func TestDNSMissingFrom_FiltersMissingOnly(t *testing.T) {
	in := []service.DNSMismatch{
		{
			Expected: domain.ExpectedDNSRecord{
				Name: "_ans.a.example.com", Type: domain.DNSRecordTXT,
				Value: "v1", Required: true, TTL: 300,
			},
			Code: "MISSING",
		},
		{
			Expected: domain.ExpectedDNSRecord{Name: "x", Type: domain.DNSRecordTXT, Value: "y"},
			Found:    "wrong",
			Code:     "MISMATCH", // filtered out
		},
	}
	got := dnsMissingFrom(in)
	if len(got) != 1 {
		t.Fatalf("want 1 missing, got %d", len(got))
	}
	if got[0].Name != "_ans.a.example.com" {
		t.Errorf("name: %q", got[0].Name)
	}
	if !got[0].Required {
		t.Error("Required flag lost in mapping")
	}
}

// The incorrect-record mappers must surface present-but-wrong records: a
// plain value MISMATCH and DNSSEC-authenticated tampering on EVERY
// DNSSEC-bearing record type (TLSA, SVCB, HTTPS) — not just TLSA, which
// was the original gap. MISSING records are excluded (they belong in the
// missing-records array). V2 and V1 classify identically, so one table
// drives both lanes.
func TestDNSIncorrectMappers_SurfaceMismatchAndAllDNSSEC(t *testing.T) {
	cases := []struct {
		name        string
		code        string
		wantSurface bool
	}{
		{"plain_value_mismatch", "MISMATCH", true},
		{"tlsa_dnssec_tampering", "TLSA_DNSSEC_MISMATCH", true},
		{"svcb_dnssec_tampering", "SVCB_DNSSEC_MISMATCH", true},
		{"https_dnssec_tampering", "HTTPS_DNSSEC_MISMATCH", true},
		{"missing_is_excluded", "MISSING", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []service.DNSMismatch{{
				Expected: domain.ExpectedDNSRecord{
					Name: "rec.example.com", Type: domain.DNSRecordSVCB, Value: "want",
				},
				Found: "wrong",
				Code:  tc.code,
			}}

			v2 := dnsIncorrectFrom(in)
			v1 := v1DNSIncorrectFrom(in)

			if !tc.wantSurface {
				if len(v2) != 0 {
					t.Errorf("V2: code %q must be excluded, got %d", tc.code, len(v2))
				}
				if len(v1) != 0 {
					t.Errorf("V1: code %q must be excluded, got %d", tc.code, len(v1))
				}
				return
			}

			if len(v2) != 1 {
				t.Fatalf("V2: code %q must surface, got %d", tc.code, len(v2))
			}
			if v2[0].Record.Name != "rec.example.com" || v2[0].Found != "wrong" || v2[0].Expected != "want" {
				t.Errorf("V2 mapping wrong: %+v", v2[0])
			}
			if len(v1) != 1 {
				t.Fatalf("V1: code %q must surface, got %d", tc.code, len(v1))
			}
			if v1[0].Name != "rec.example.com" || v1[0].Found != "wrong" || v1[0].Expected != "want" {
				t.Errorf("V1 mapping wrong: %+v", v1[0])
			}
		})
	}
}

func TestDNSMissingFrom_EmptyInputReturnsNil(t *testing.T) {
	if got := dnsMissingFrom(nil); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
}

// ----- V1 DNS mapper parity (same shape, different next-step prefix) -----

func TestV1DNSMissingFrom_FiltersMissingOnly(t *testing.T) {
	in := []service.DNSMismatch{
		{Expected: domain.ExpectedDNSRecord{Name: "a"}, Code: "MISSING"},
		{Expected: domain.ExpectedDNSRecord{Name: "b"}, Code: "MISMATCH"},
	}
	got := v1DNSMissingFrom(in)
	if len(got) != 1 || got[0].Name != "a" {
		t.Errorf("got %+v", got)
	}
}

// ----- V1 renewal mappers -----

func TestMapV1RenewalStatus_ActiveAndFailed(t *testing.T) {
	ansName, _ := domain.NewAnsName(mustSemVerForHelpers(t, 1, 0, 0), "a.example.com")
	_ = ansName

	now := time.Now()
	pending := &domain.ServerCertificateRenewal{
		RenewalType: domain.RenewalTypeCSR,
		ServerCsrID: "csr-1",
		Validation: domain.RenewalValidation{
			Status:    domain.ValidationPending,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	resp := mapV1RenewalStatus("agent-1", &service.GetRenewalResult{Renewal: pending, FQDN: "a.example.com"})
	if resp.CsrID != "csr-1" {
		t.Errorf("csr: %q", resp.CsrID)
	}
	if resp.RenewalType != "SERVER_CSR" {
		t.Errorf("renewal type: %q", resp.RenewalType)
	}
	if resp.NextStep.Endpoint == "" {
		t.Error("NextStep.Endpoint empty")
	}

	// Failed renewal surfaces FailureReason.
	failed := *pending
	failed.FailureReason = "dns lookup failed"
	failed.Validation.Status = domain.ValidationFailed
	resp2 := mapV1RenewalStatus("agent-1", &service.GetRenewalResult{Renewal: &failed, FQDN: "a.example.com"})
	if resp2.FailureReason != "dns lookup failed" {
		t.Errorf("failure reason lost: %q", resp2.FailureReason)
	}
}

func TestMapV1RenewalVerification_SyncAndAsync(t *testing.T) {
	// Async case (Sync=false) yields ISSUING_CERTIFICATE.
	r := &domain.ServerCertificateRenewal{ServerCsrID: "csr-9"}
	resp := mapV1RenewalVerification("agent-9", &service.VerifyRenewalACMEResult{
		Renewal: r,
		Sync:    false,
	})
	if resp.Status != "ISSUING_CERTIFICATE" {
		t.Errorf("async status: %q", resp.Status)
	}
	if resp.CsrID != "csr-9" {
		t.Errorf("csr lost in mapping: %q", resp.CsrID)
	}

	// Sync case yields COMPLETED.
	resp2 := mapV1RenewalVerification("agent-9", &service.VerifyRenewalACMEResult{
		Renewal: r,
		Sync:    true,
	})
	if resp2.Status != "COMPLETED" {
		t.Errorf("sync status: %q", resp2.Status)
	}
}

// mustSemVerForHelpers — small helper so the test file stays
// self-contained and doesn't conflict with mustSemVer from sqlite
// tests.
func mustSemVerForHelpers(t *testing.T, major, minor, patch int) domain.SimplifiedSemVer {
	t.Helper()
	v, err := domain.NewSemVer(major, minor, patch)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ----- deriveRenewalStatus state machine -----
//
// The five-arm switch in deriveRenewalStatus is the source of truth
// for the wire-format renewal status enum. Each branch matters
// because the response shape downstream (status text, NextStep,
// FailureReason field) depends on it. Pre-coverage we only saw the
// happy paths through integration tests; this table-driven test
// pins every arm.

func TestDeriveRenewalStatus_AllBranches(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		in   *domain.ServerCertificateRenewal
		want string
	}{
		{
			name: "failure-reason-set wins over everything",
			in: &domain.ServerCertificateRenewal{
				FailureReason: "boom",
				CompletedAt:   now,
				Validation:    domain.RenewalValidation{Status: domain.ValidationVerified},
			},
			want: renewalStatusFailed,
		},
		{
			name: "completed-at-set yields COMPLETED",
			in: &domain.ServerCertificateRenewal{
				CompletedAt: now,
				Validation:  domain.RenewalValidation{Status: domain.ValidationVerified},
			},
			want: renewalStatusCompleted,
		},
		{
			name: "expired window yields EXPIRED",
			in: &domain.ServerCertificateRenewal{
				Validation: domain.RenewalValidation{
					Status:    domain.ValidationPending,
					ExpiresAt: now.Add(-time.Hour),
				},
			},
			want: renewalStatusExpired,
		},
		{
			name: "verified BYOC completes synchronously",
			in: &domain.ServerCertificateRenewal{
				RenewalType: domain.RenewalTypeBYOC,
				Validation: domain.RenewalValidation{
					Status:    domain.ValidationVerified,
					ExpiresAt: now.Add(time.Hour),
				},
			},
			want: renewalStatusCompleted,
		},
		{
			name: "verified CSR is still ISSUING_CERTIFICATE",
			in: &domain.ServerCertificateRenewal{
				RenewalType: domain.RenewalTypeCSR,
				Validation: domain.RenewalValidation{
					Status:    domain.ValidationVerified,
					ExpiresAt: now.Add(time.Hour),
				},
			},
			want: renewalStatusIssuingCertificate,
		},
		{
			name: "default (pending validation) when nothing else applies",
			in: &domain.ServerCertificateRenewal{
				Validation: domain.RenewalValidation{
					Status:    domain.ValidationPending,
					ExpiresAt: now.Add(time.Hour),
				},
			},
			want: renewalStatusPendingValidation,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveRenewalStatus(tc.in, now); got != tc.want {
				t.Errorf("deriveRenewalStatus: got %q want %q", got, tc.want)
			}
		})
	}
}

// mapRenewalStatus carries the FailureReason field through only when
// it's set. Pre-coverage the FailureReason-set branch was dark.
func TestMapRenewalStatus_FailureReasonField(t *testing.T) {
	now := time.Now()
	failed := &domain.ServerCertificateRenewal{
		RenewalType:   domain.RenewalTypeBYOC,
		ServerCsrID:   "csr-x",
		FailureReason: "validation expired",
		Validation: domain.RenewalValidation{
			Status:    domain.ValidationFailed,
			ExpiresAt: now.Add(-time.Hour),
		},
	}
	resp := mapRenewalStatus("agent-1", &service.GetRenewalResult{Renewal: failed, FQDN: "a.example.com"})
	if resp.FailureReason != "validation expired" {
		t.Errorf("FailureReason: got %q want validation expired", resp.FailureReason)
	}
	if resp.Status != renewalStatusFailed {
		t.Errorf("Status: got %q want FAILED", resp.Status)
	}
}

func TestMapRenewalStatus_NoFailureReason(t *testing.T) {
	now := time.Now()
	pending := &domain.ServerCertificateRenewal{
		RenewalType: domain.RenewalTypeCSR,
		ServerCsrID: "csr-x",
		Validation: domain.RenewalValidation{
			Status:    domain.ValidationPending,
			ExpiresAt: now.Add(time.Hour),
		},
	}
	resp := mapRenewalStatus("agent-1", &service.GetRenewalResult{Renewal: pending, FQDN: "a.example.com"})
	if resp.FailureReason != "" {
		t.Errorf("FailureReason should be empty for non-failed renewal; got %q", resp.FailureReason)
	}
}

// mapRenewalSubmission only ever produces a PENDING_VALIDATION status;
// pin both that and the next-step shape so the wire contract is
// locked.
func TestMapRenewalSubmission_PendingValidation(t *testing.T) {
	now := time.Now()
	res := &service.SubmitRenewalResult{
		Renewal: &domain.ServerCertificateRenewal{
			RenewalType: domain.RenewalTypeBYOC,
			Validation:  domain.RenewalValidation{ExpiresAt: now.Add(time.Hour)},
		},
		CsrID: "csr-1",
	}
	resp := mapRenewalSubmission("agent-1", res)
	if resp.Status != renewalStatusPendingValidation {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
	if resp.NextStep.Action != "VALIDATE_DOMAIN" {
		t.Errorf("nextStep.Action: got %q", resp.NextStep.Action)
	}
	// RenewalType is echoed verbatim from the domain enum.
	if resp.RenewalType != string(domain.RenewalTypeBYOC) {
		t.Errorf("renewalType: got %q want %q", resp.RenewalType, domain.RenewalTypeBYOC)
	}
	if resp.CsrID != "csr-1" {
		t.Errorf("csrID lost in mapping: %q", resp.CsrID)
	}
	if len(resp.Links) == 0 {
		t.Error("submission response should carry a self link")
	}
}

// nextStepFor has six cases (one per status enum value plus the
// default fallback). Touching every arm proves the wire-format
// Action / Endpoint / Description triples don't drift.
func TestNextStepFor_AllStatuses(t *testing.T) {
	cases := map[string]string{
		renewalStatusPendingValidation:  "VALIDATE_DOMAIN",
		renewalStatusIssuingCertificate: "WAIT",
		renewalStatusCompleted:          "CONFIGURE_DNS",
		renewalStatusFailed:             "CONFIGURE_DNS",
		renewalStatusExpired:            "CONFIGURE_DNS",
		"UNKNOWN_STATUS":                "WAIT", // default arm
	}
	for status, wantAction := range cases {
		t.Run(status, func(t *testing.T) {
			ns := nextStepFor("agent-x", status)
			if ns.Action != wantAction {
				t.Errorf("action: got %q want %q", ns.Action, wantAction)
			}
			// Endpoint always carries the V2 prefix; defends against
			// a refactor that forgets to scope per agent.
			if ns.Endpoint == "" {
				t.Error("endpoint empty")
			}
		})
	}
}
