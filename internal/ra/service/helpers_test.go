package service

// White-box tests for the small pure helpers in helpers.go. These are
// exercised end-to-end by the lifecycle integration tests, but
// branch-level coverage on the helpers themselves is patchy because
// the integration tests follow happy paths. Direct table-driven tests
// here cover the empty/nil and multi-input branches that the
// integration suite would only hit on rare lifecycle transitions.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ----- fingerprintOf -----

func TestFingerprintOf_HappyPath(t *testing.T) {
	pemStr := selfSignedCertPEM(t)
	got, err := fingerprintOf(pemStr)
	if err != nil {
		t.Fatalf("fingerprintOf: %v", err)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("missing SHA256: prefix; got %q", got)
	}
	// 64 hex chars after the prefix.
	if len(got) != len("SHA256:")+64 {
		t.Errorf("hex length: got %d want %d", len(got), len("SHA256:")+64)
	}
}

func TestFingerprintOf_NoPEMBlock(t *testing.T) {
	if _, err := fingerprintOf("not a pem"); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestFingerprintOf_WrongPEMType(t *testing.T) {
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte{0x00, 0x01, 0x02},
	}))
	if _, err := fingerprintOf(pemStr); err == nil {
		t.Error("expected error for non-CERTIFICATE PEM type")
	}
}

// ----- agentCertExpiry -----

func TestAgentCertExpiry_NoInputsReturnsEmpty(t *testing.T) {
	if got := agentCertExpiry(nil, nil, time.Now()); got != "" {
		t.Errorf("nil inputs should yield empty string; got %q", got)
	}
}

func TestAgentCertExpiry_EarliestStoredCertWins(t *testing.T) {
	now := time.Now().UTC()
	earliest := now.Add(24 * time.Hour)
	later := now.Add(72 * time.Hour)
	stored := []*domain.StoredCertificate{
		{ExpirationTimestamp: later, Status: domain.CertStatusValid},
		{ExpirationTimestamp: earliest, Status: domain.CertStatusValid},
	}
	got := agentCertExpiry(stored, nil, now)
	if got == "" {
		t.Fatal("expected non-empty expiry")
	}
	want := earliest.Format(time.RFC3339)
	if got != want {
		t.Errorf("expiry: got %q want %q", got, want)
	}
}

func TestAgentCertExpiry_RevokedCertsIgnored(t *testing.T) {
	now := time.Now().UTC()
	stored := []*domain.StoredCertificate{
		// Revoked status → IsValid returns false → ignored.
		{ExpirationTimestamp: now.Add(24 * time.Hour), Status: domain.CertStatusRevoked},
		// Valid status with later expiry → wins.
		{ExpirationTimestamp: now.Add(72 * time.Hour), Status: domain.CertStatusValid},
	}
	got := agentCertExpiry(stored, nil, now)
	want := now.Add(72 * time.Hour).Format(time.RFC3339)
	if got != want {
		t.Errorf("expiry: got %q want %q (only valid cert should count)", got, want)
	}
}

func TestAgentCertExpiry_BYOCEarlierThanStored(t *testing.T) {
	now := time.Now().UTC()
	stored := []*domain.StoredCertificate{
		{ExpirationTimestamp: now.Add(72 * time.Hour), Status: domain.CertStatusValid},
	}
	byoc := &domain.ByocServerCertificate{
		ValidToTimestamp: now.Add(24 * time.Hour),
	}
	got := agentCertExpiry(stored, byoc, now)
	want := now.Add(24 * time.Hour).Format(time.RFC3339)
	if got != want {
		t.Errorf("expiry: got %q want %q (BYOC should win)", got, want)
	}
}

func TestAgentCertExpiry_BYOCWithZeroValidToIgnored(t *testing.T) {
	now := time.Now().UTC()
	stored := []*domain.StoredCertificate{
		{ExpirationTimestamp: now.Add(72 * time.Hour), Status: domain.CertStatusValid},
	}
	byoc := &domain.ByocServerCertificate{} // zero ValidTo
	got := agentCertExpiry(stored, byoc, now)
	want := now.Add(72 * time.Hour).Format(time.RFC3339)
	if got != want {
		t.Errorf("expiry: got %q want %q (zero BYOC.ValidTo should be skipped)", got, want)
	}
}

func TestAgentCertExpiry_NilCertEntryIgnored(t *testing.T) {
	// The `c == nil` guard at the top of the loop must short-circuit
	// gracefully when callers slip a nil into the slice.
	now := time.Now().UTC()
	stored := []*domain.StoredCertificate{
		nil,
		{ExpirationTimestamp: now.Add(24 * time.Hour), Status: domain.CertStatusValid},
	}
	got := agentCertExpiry(stored, nil, now)
	if got == "" {
		t.Error("expected expiry string from the non-nil cert")
	}
}

// ----- metadataHashesFromEndpoints -----

func TestMetadataHashesFromEndpoints_EmptyReturnsNil(t *testing.T) {
	if got := metadataHashesFromEndpoints(nil); got != nil {
		t.Errorf("nil eps should yield nil map; got %v", got)
	}
	if got := metadataHashesFromEndpoints([]domain.AgentEndpoint{}); got != nil {
		t.Errorf("empty eps should yield nil map; got %v", got)
	}
}

func TestMetadataHashesFromEndpoints_AllEmptyHashesReturnsNil(t *testing.T) {
	eps := []domain.AgentEndpoint{
		{Protocol: "MCP", MetadataHash: ""},
		{Protocol: "A2A", MetadataHash: ""},
	}
	if got := metadataHashesFromEndpoints(eps); got != nil {
		t.Errorf("all-empty hashes should yield nil; got %v", got)
	}
}

func TestMetadataHashesFromEndpoints_FirstHashWinsPerProtocol(t *testing.T) {
	eps := []domain.AgentEndpoint{
		{Protocol: "MCP", MetadataHash: "SHA256:first"},
		{Protocol: "A2A", MetadataHash: "SHA256:other"},
		{Protocol: "MCP", MetadataHash: "SHA256:duplicate"}, // ignored
	}
	got := metadataHashesFromEndpoints(eps)
	if got["MCP"] != "SHA256:first" {
		t.Errorf("MCP: got %q want SHA256:first", got["MCP"])
	}
	if got["A2A"] != "SHA256:other" {
		t.Errorf("A2A: got %q want SHA256:other", got["A2A"])
	}
	if len(got) != 2 {
		t.Errorf("entries: got %d want 2", len(got))
	}
}

// ----- helpers -----

// selfSignedCertPEM returns a freshly-generated self-signed
// certificate PEM string. Used only by fingerprintOf tests; the cert
// content is irrelevant — only the fact that it parses as a valid
// X.509 DER block matters.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ----- applyDNSRecordStyles -----

// TestApplyDNSRecordStyles covers the V1-pin / V2-default / V2-validate
// branches, including the INVALID_DNS_RECORD_STYLE error path and
// duplicate-element deduplication. The integration tests follow happy
// paths through RegisterAgent and don't reach the invalid-element
// branch directly.
func TestApplyDNSRecordStyles(t *testing.T) {
	tests := []struct {
		name        string
		req         RegisterRequest
		wantStyles  []domain.DNSRecordStyle
		wantErrCode string
	}{
		{
			name: "v1_pins_to_ans_txt_ignoring_request_field",
			req: RegisterRequest{
				SchemaVersion:   "V1",
				DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			},
			wantStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleTXT},
		},
		{
			name:       "v2_nil_normalizes_to_default",
			req:        RegisterRequest{SchemaVersion: "V2"},
			wantStyles: domain.DefaultDNSRecordStyles(),
		},
		{
			name:       "v2_empty_slice_normalizes_to_default",
			req:        RegisterRequest{SchemaVersion: "V2", DNSRecordStyles: []domain.DNSRecordStyle{}},
			wantStyles: domain.DefaultDNSRecordStyles(),
		},
		{
			name:       "unset_schema_treated_as_v2_default",
			req:        RegisterRequest{},
			wantStyles: domain.DefaultDNSRecordStyles(),
		},
		{
			name: "v2_valid_ans_svcb_only",
			req: RegisterRequest{
				SchemaVersion:   "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			},
			wantStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
		},
		{
			name: "v2_valid_ans_txt_only",
			req: RegisterRequest{
				SchemaVersion:   "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleTXT},
			},
			wantStyles: []domain.DNSRecordStyle{domain.DNSRecordStyleTXT},
		},
		{
			name: "v2_valid_union_preserves_order",
			req: RegisterRequest{
				SchemaVersion: "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{
					domain.DNSRecordStyleSVCB,
					domain.DNSRecordStyleTXT,
				},
			},
			wantStyles: []domain.DNSRecordStyle{
				domain.DNSRecordStyleSVCB,
				domain.DNSRecordStyleTXT,
			},
		},
		{
			name: "v2_duplicate_elements_deduped",
			req: RegisterRequest{
				SchemaVersion: "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{
					domain.DNSRecordStyleSVCB,
					domain.DNSRecordStyleSVCB,
					domain.DNSRecordStyleTXT,
				},
			},
			wantStyles: []domain.DNSRecordStyle{
				domain.DNSRecordStyleSVCB,
				domain.DNSRecordStyleTXT,
			},
		},
		{
			name: "v2_invalid_element_rejected",
			req: RegisterRequest{
				SchemaVersion:   "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyle("garbage")},
			},
			wantErrCode: "INVALID_DNS_RECORD_STYLE",
		},
		{
			// CONSTANT_CASE is the wire form. lowercase is rejected so the
			// V2 enum stays consistent with every other enum on the spec.
			name: "v2_lowercase_element_rejected_as_invalid",
			req: RegisterRequest{
				SchemaVersion:   "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyle("ans_svcb")},
			},
			wantErrCode: "INVALID_DNS_RECORD_STYLE",
		},
		{
			// First valid, second invalid — error surfaces at the
			// invalid element, no partial state stamped on the aggregate.
			name: "v2_mixed_valid_then_invalid_rejected",
			req: RegisterRequest{
				SchemaVersion: "V2",
				DNSRecordStyles: []domain.DNSRecordStyle{
					domain.DNSRecordStyleSVCB,
					domain.DNSRecordStyle("garbage"),
				},
			},
			wantErrCode: "INVALID_DNS_RECORD_STYLE",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &domain.AgentRegistration{}
			err := applyDNSRecordStyles(reg, tc.req)
			if tc.wantErrCode != "" {
				if err == nil {
					t.Fatalf("want error code %q, got nil", tc.wantErrCode)
				}
				var verr *domain.Error
				if !errors.As(err, &verr) {
					t.Fatalf("want *domain.Error, got %T: %v", err, err)
				}
				if verr.Code != tc.wantErrCode {
					t.Errorf("code: got %q want %q", verr.Code, tc.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !sameStyles(reg.DNSRecordStyles, tc.wantStyles) {
				t.Errorf("DNSRecordStyles: got %v want %v", reg.DNSRecordStyles, tc.wantStyles)
			}
		})
	}
}

// TestApplyDNSRecordStyles_ErrorMessageListsValidValues confirms the
// error detail enumerates the canonical valid set so SDK authors get
// an actionable message. Sourced from domain.ValidDNSRecordStyles().
func TestApplyDNSRecordStyles_ErrorMessageListsValidValues(t *testing.T) {
	reg := &domain.AgentRegistration{}
	err := applyDNSRecordStyles(reg, RegisterRequest{
		SchemaVersion:   "V2",
		DNSRecordStyles: []domain.DNSRecordStyle{domain.DNSRecordStyle("garbage")},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range domain.ValidDNSRecordStyles() {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message must list %q; got %q", want, err.Error())
		}
	}
}

// sameStyles compares two style slices for set-equal-with-order. Used
// by TestApplyDNSRecordStyles to assert the expected ordering after
// dedup without pulling in reflect.DeepEqual semantics that distinguish
// nil from empty.
func sameStyles(a, b []domain.DNSRecordStyle) bool {
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
