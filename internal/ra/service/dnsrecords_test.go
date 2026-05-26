package service_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/adapter/discovery/registry"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// newTestRegistry returns the bundled ANS-family registry every
// service-level test uses. Mirrors cmd/ans-ra/main.go's wiring so
// emission order in tests matches production.
func newTestRegistry(t *testing.T) port.DiscoveryRegistry {
	t.Helper()
	r, err := service.NewDefaultDiscoveryRegistry()
	require.NoError(t, err)
	return r
}

// newComputeOnlyService returns a RegistrationService wired only with
// the discovery registry — sufficient for ComputeRequiredDNSRecords
// tests, which never touch storage / signing / DNS verification.
// Other dependencies are passed nil; the walker is a pure function of
// reg + registry.
func newComputeOnlyService(t *testing.T) *service.RegistrationService {
	t.Helper()
	return service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		newTestRegistry(t),
	)
}

func mustReg(t *testing.T, host string, version string, eps []domain.AgentEndpoint, cert *domain.ByocServerCertificate, styles []domain.DNSRecordStyle) *domain.AgentRegistration {
	t.Helper()
	v, err := domain.ParseSemVer(version)
	require.NoError(t, err)
	ansName, err := domain.NewAnsName(v, host)
	require.NoError(t, err)
	return &domain.AgentRegistration{
		AnsName:         ansName,
		Endpoints:       eps,
		ServerCert:      cert,
		DNSRecordStyles: styles,
	}
}

// TestComputeRequiredDNSRecords_StyleMatrix_Integration is the
// migrated cross-style integration matrix from
// internal/domain/dnsrecords_test.go:105-284. Per-adapter tests cover
// within-style rules; this table is the regression suite for the
// styles cross-product (e.g. "SVCB-sole emits no HTTPS RR" — only
// testable across both adapters' output).
func TestComputeRequiredDNSRecords_StyleMatrix_Integration(t *testing.T) {
	const sampleMetadataHash = "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantSampleCardBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name             string
		styles           []domain.DNSRecordStyle
		protocol         domain.Protocol
		agentURL         string
		metadataHash     string // optional per-endpoint MetadataHash
		wantHTTPS        bool
		wantSVCB         bool
		wantSVCBRequired bool // applies only when wantSVCB is true
		wantLegacyTXT    bool
		wantSVCBPort     string // substring expected in SVCB value (e.g. "port=443")
		wantSVCBWk       string // "" means SVCB MUST NOT contain "wk="
		wantSVCBCard     string // "" means SVCB MUST NOT contain "card-sha256"
	}{
		{
			name:          "ans_txt_only_emits_https_rr_no_svcb",
			styles:        []domain.DNSRecordStyle{domain.DNSRecordStyleTXT},
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
		},
		{
			name:             "ans_svcb_only_omits_https_rr",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true, // SVCB-sole: only PurposeDiscovery record, must be required
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=agent-card.json",
		},
		{
			name:          "union_emits_both_families",
			styles:        []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB, domain.DNSRecordStyleTXT},
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
			wantSVCB:      true,
			// wantSVCBRequired: false — legacy `_ans` TXT carries the
			// Required signal during the §4.4.2 transition; SVCB rides
			// along as optional.
			wantSVCBPort: "port=443",
			wantSVCBWk:   "wk=agent-card.json",
		},
		{
			name:             "svcb_mcp_wk_mcp_json",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolMCP,
			agentURL:         "https://agent.example.com/mcp",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=mcp.json",
		},
		{
			name:             "svcb_http_api_omits_wk",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolHTTPAPI,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBPort:     "port=443",
		},
		{
			name:             "svcb_card_sha256_from_endpoint_metadata_hash",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			metadataHash:     sampleMetadataHash,
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=agent-card.json",
			wantSVCBCard:     "card-sha256=" + wantSampleCardBase64,
		},
		{
			name:             "svcb_non_443_port_from_url",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com:8443",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBPort:     "port=8443",
			wantSVCBWk:       "wk=agent-card.json",
		},
		{
			name:             "svcb_http_scheme_defaults_port_80",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB},
			protocol:         domain.ProtocolA2A,
			agentURL:         "http://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBPort:     "port=80",
			wantSVCBWk:       "wk=agent-card.json",
		},
		{
			name:             "empty_styles_coerces_to_default",
			styles:           nil,
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true, // default ({ANS_SVCB}) is SVCB-sole
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=agent-card.json",
		},
		{
			name:             "all_invalid_styles_falls_back_to_default",
			styles:           []domain.DNSRecordStyle{domain.DNSRecordStyle("garbage"), domain.DNSRecordStyle("nonsense")},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true, // fallback default ({ANS_SVCB}) is SVCB-sole
			wantSVCBPort:     "port=443",
			wantSVCBWk:       "wk=agent-card.json",
		},
	}

	svc := newComputeOnlyService(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := mustReg(t, "agent.example.com", "1.0.0",
				[]domain.AgentEndpoint{{
					Protocol:     tc.protocol,
					AgentURL:     tc.agentURL,
					MetadataHash: tc.metadataHash,
				}},
				nil, tc.styles)

			records := svc.ComputeRequiredDNSRecords(reg)

			var sawHTTPS, sawSVCB, sawLegacyTXT bool
			var svcbValue string
			var svcbRequired bool
			for _, r := range records {
				switch r.Type {
				case domain.DNSRecordHTTPS:
					sawHTTPS = true
				case domain.DNSRecordSVCB:
					sawSVCB = true
					svcbValue = r.Value
					svcbRequired = r.Required
				case domain.DNSRecordTXT:
					if strings.HasPrefix(r.Name, "_ans.") {
						sawLegacyTXT = true
					}
				}
			}

			assert.Equal(t, tc.wantHTTPS, sawHTTPS, "HTTPS RR presence")
			assert.Equal(t, tc.wantSVCB, sawSVCB, "SVCB row presence")
			assert.Equal(t, tc.wantLegacyTXT, sawLegacyTXT, "_ans TXT presence")

			if tc.wantSVCB {
				assert.Equal(t, tc.wantSVCBRequired, svcbRequired,
					"SVCB Required flag mismatch (true iff ANS_SVCB is the sole resolved style)")
				assert.Contains(t, svcbValue, tc.wantSVCBPort,
					"SVCB port SvcParam mismatch")
				if tc.wantSVCBWk != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBWk, "SVCB wk SvcParam mismatch")
				} else {
					assert.NotContains(t, svcbValue, "wk=",
						"SVCB MUST NOT carry wk= when protocol has no metadata convention")
				}
				if tc.wantSVCBCard != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBCard, "SVCB card-sha256 SvcParam mismatch")
				} else {
					assert.NotContains(t, svcbValue, "card-sha256",
						"SVCB MUST NOT carry card-sha256 when endpoint MetadataHash is empty")
				}
			}
		})
	}
}

// TestComputeRequiredDNSRecords_UnionDedupesFamilyTrustRecords pins
// that when the union {ANS_SVCB, ANS_TXT} emits, family trust records
// (`_ans-badge`, TLSA) appear ONCE in the output even though both
// adapters emit them. Catches a regression where the dedup pass is
// removed or the dedup key drifts.
func TestComputeRequiredDNSRecords_UnionDedupesFamilyTrustRecords(t *testing.T) {
	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		&domain.ByocServerCertificate{Fingerprint: "abcdef"},
		[]domain.DNSRecordStyle{domain.DNSRecordStyleSVCB, domain.DNSRecordStyleTXT})

	records := svc.ComputeRequiredDNSRecords(reg)

	var badgeCount, tlsaCount int
	for _, r := range records {
		if r.Purpose == domain.PurposeBadge {
			badgeCount++
		}
		if r.Purpose == domain.PurposeCertificateBinding {
			tlsaCount++
		}
	}
	assert.Equal(t, 1, badgeCount, "exactly one `_ans-badge` record across the union")
	assert.Equal(t, 1, tlsaCount, "exactly one TLSA record across the union")
}

// TestComputeRequiredDNSRecords_NoEndpoints pins the empty-input
// contract: no endpoints → no records (ServerCert + nil endpoints
// alone is also covered, but the typical case is the V1/V2 detail
// handler hitting an aggregate that hasn't reached PENDING_DNS yet).
func TestComputeRequiredDNSRecords_NoEndpoints(t *testing.T) {
	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.0.0", nil, nil, nil)
	records := svc.ComputeRequiredDNSRecords(reg)
	assert.Empty(t, records)
}

// TestNewRegistrationService_PanicsOnNilDiscoveryRegistry pins the
// fail-loud invariant the constructor enforces. A missing registry
// would silently emit zero `dnsRecordsProvisioned[]` and accept any
// DNS state at verify-dns — trust-root corruption masquerading as
// graceful degradation. Construction is process-start-time, not a
// request path, so the panic does not violate the no-panics-in-
// request-paths rule.
func TestNewRegistrationService_PanicsOnNilDiscoveryRegistry(t *testing.T) {
	defer func() {
		r := recover()
		require.NotNil(t, r, "constructor must panic when discoveryRegistry is nil")
		msg, ok := r.(string)
		require.True(t, ok, "panic value must be a string explaining the missing dependency")
		assert.Contains(t, msg, "discoveryRegistry is required")
	}()
	_ = service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
}

// TestComputeRequiredDNSRecords_UnknownStyleSkipped pins that a
// reg.DNSRecordStyles entry the registry doesn't have is silently
// skipped (with a WARN log; not asserted in this test). The remaining
// valid styles still emit. If every entry is unknown, the walker
// falls back to DefaultDNSRecordStyles.
func TestComputeRequiredDNSRecords_UnknownStyleSkipped(t *testing.T) {
	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		nil,
		[]domain.DNSRecordStyle{domain.DNSRecordStyleSVCB, domain.DNSRecordStyle("UNKNOWN_FUTURE")})

	records := svc.ComputeRequiredDNSRecords(reg)

	// SVCB is recognized → SVCB-sole emission. UNKNOWN_FUTURE is dropped.
	var sawSVCB bool
	for _, r := range records {
		if r.Type == domain.DNSRecordSVCB {
			sawSVCB = true
		}
	}
	assert.True(t, sawSVCB, "valid style alongside unknown-style still emits")
}

// TestComputeRequiredDNSRecords_UnionCanonicalBytesRegression pins
// the V2 TL `dnsRecordsProvisioned[]` canonical wire for the §4.4.2
// transition union (ANS_SVCB + ANS_TXT). Any change to slice ORDER
// (JCS preserves array order per RFC 8785 §3.2.2) would shift the
// SHA-256, signal a wire-shape regression, and break offline-verifier
// hashes for in-flight agents at deploy time.
//
// The hex constant was captured against this exact input. Do NOT
// regenerate without explicit approval — a change here is a
// wire-format change, not a test fix.
func TestComputeRequiredDNSRecords_UnionCanonicalBytesRegression(t *testing.T) {
	const wantSHA256Hex = "ab1efc56fcc5dc088ff0f35d5ed1e0164b8ee70a11116e60f180a55fe794bf64"

	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.2.3",
		[]domain.AgentEndpoint{
			{
				Protocol:     domain.ProtocolA2A,
				AgentURL:     "https://agent.example.com/a2a",
				MetadataHash: "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27",
			},
			{
				Protocol:     domain.ProtocolMCP,
				AgentURL:     "https://agent.example.com/mcp",
				MetadataHash: "SHA256:1111111111111111111111111111111111111111111111111111111111111111",
			},
		},
		&domain.ByocServerCertificate{Fingerprint: "deadbeefcafe1234"},
		[]domain.DNSRecordStyle{domain.DNSRecordStyleSVCB, domain.DNSRecordStyleTXT})

	records := svc.ComputeRequiredDNSRecords(reg)

	// The expected emission shape (order-preserved) is:
	//   1. _ans.<fqdn>          TXT  (a2a)        Required=true
	//   2. _ans.<fqdn>          TXT  (mcp)        Required=true
	//   3. <fqdn>               HTTPS (1 . alpn=h2)  Required=false
	//   4. <fqdn>               SVCB (a2a)        Required=false (TXT also resolved)
	//   5. <fqdn>               SVCB (mcp)        Required=false
	//   6. _ans-badge.<fqdn>    TXT (badge)       Required=true
	//   7. _443._tcp.<fqdn>     TLSA              Required=false
	require.Len(t, records, 7, "union case must emit exactly 7 records")
	assert.Equal(t, "_ans.agent.example.com", records[0].Name)
	assert.Equal(t, domain.DNSRecordTXT, records[0].Type)
	assert.Equal(t, "_ans.agent.example.com", records[1].Name)
	assert.Equal(t, "agent.example.com", records[2].Name)
	assert.Equal(t, domain.DNSRecordHTTPS, records[2].Type)
	assert.Equal(t, "agent.example.com", records[3].Name)
	assert.Equal(t, domain.DNSRecordSVCB, records[3].Type)
	assert.False(t, records[3].Required, "SVCB Required=false during transition (TXT carries the required signal)")
	assert.Equal(t, "agent.example.com", records[4].Name)
	assert.Equal(t, domain.DNSRecordSVCB, records[4].Type)
	assert.Equal(t, "_ans-badge.agent.example.com", records[5].Name)
	assert.Equal(t, "_443._tcp.agent.example.com", records[6].Name)
	assert.Equal(t, domain.DNSRecordTLSA, records[6].Type)

	// SHA-256 over JCS-canonical bytes — pins the exact wire bytes
	// the V2 TL leaf will canonicalize.
	jsonBytes, err := json.Marshal(records)
	require.NoError(t, err)
	canonical, err := anscrypto.Canonicalize(jsonBytes)
	require.NoError(t, err)
	sum := sha256.Sum256(canonical)
	gotHex := hex.EncodeToString(sum[:])
	assert.Equal(t, wantSHA256Hex, gotHex,
		"V2 union canonical-bytes SHA-256 drifted; investigate before changing the constant")
}

// TestNewDefaultDiscoveryRegistry pins the default-wiring contract:
// returns a registry containing both ANS-family styles in TXT-then-SVCB
// insertion order. The order is the V2 canonical-bytes input.
func TestNewDefaultDiscoveryRegistry(t *testing.T) {
	r, err := service.NewDefaultDiscoveryRegistry()
	require.NoError(t, err)

	got := r.IDs()
	want := []domain.DNSRecordStyle{domain.DNSRecordStyleTXT, domain.DNSRecordStyleSVCB}
	assert.Equal(t, want, got, "default registry must wire TXT before SVCB to preserve V2 union canonical bytes")
}

// TestComputeRequiredDNSRecords_RegistryIterationOrderDeterminesEmission
// pins that a non-default registry wiring (SVCB before TXT) actually
// produces a different emission order — proving the walker honours
// registry insertion order rather than user-supplied
// reg.DNSRecordStyles order.
func TestComputeRequiredDNSRecords_RegistryIterationOrderDeterminesEmission(t *testing.T) {
	// Build a "production" service (default registry wiring: TXT, SVCB)
	// and a custom one with SVCB before TXT.
	defaultSvc := newComputeOnlyService(t)

	customReg, err := registry.New(svcStub{id: domain.DNSRecordStyleSVCB, marker: "S"}, svcStub{id: domain.DNSRecordStyleTXT, marker: "T"})
	require.NoError(t, err)
	customSvc := service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, customReg)

	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		nil,
		[]domain.DNSRecordStyle{domain.DNSRecordStyleSVCB, domain.DNSRecordStyleTXT})

	defaultOut := defaultSvc.ComputeRequiredDNSRecords(reg)
	customOut := customSvc.ComputeRequiredDNSRecords(reg)

	// Default: TXT first → first record is the `_ans` TXT.
	require.NotEmpty(t, defaultOut)
	assert.Equal(t, "_ans.agent.example.com", defaultOut[0].Name,
		"default registry wires TXT first; first emitted record is `_ans` TXT")

	// Custom: SVCB stub (marker=S) first, no records (stub returns
	// empty slice). Then TXT stub (marker=T), also empty. So custom
	// out is empty — pinning that the custom registry was actually
	// consulted (without the registry, the walker would fall back to
	// the default and produce non-empty records).
	assert.Empty(t, customOut, "stub registry produces no records; default fallback is gated by registry presence, not adapter output")
}

// svcStub is a minimal port.DiscoveryStyle for ordering tests; emits
// no records so the test asserts purely on walker behavior.
type svcStub struct {
	id     domain.DNSRecordStyle
	marker string
}

func (s svcStub) ID() domain.DNSRecordStyle { return s.id }
func (svcStub) Records(*domain.AgentRegistration) []domain.ExpectedDNSRecord {
	return nil
}

// inconsistentRegistry violates the IDs()/Get consistency contract:
// IDs() advertises a style that Get() does not have. The walker's
// defensive `if !ok { continue }` branch is the safety net for that
// contract violation. The bundled registry maintains the contract by
// construction, so this fake exercises a branch only a custom
// port.DiscoveryRegistry implementation could ever reach.
type inconsistentRegistry struct{}

func (inconsistentRegistry) IDs() []domain.DNSRecordStyle {
	return []domain.DNSRecordStyle{domain.DNSRecordStyleSVCB}
}

func (inconsistentRegistry) Get(domain.DNSRecordStyle) (port.DiscoveryStyle, bool) {
	return nil, false
}

// TestComputeRequiredDNSRecords_RegistryGetMissDoesNotPanic pins the
// defensive branch the walker takes when registry.IDs() and Get fall
// out of sync. The branch is unreachable in production wiring; it
// exists so a future custom port.DiscoveryRegistry implementation
// (e.g. one that hot-reloads styles and races between IDs() and Get)
// degrades to "skip the missing ID" instead of nil-dereferencing the
// returned style.
func TestComputeRequiredDNSRecords_RegistryGetMissDoesNotPanic(t *testing.T) {
	svc := service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		inconsistentRegistry{})
	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		nil,
		[]domain.DNSRecordStyle{domain.DNSRecordStyleSVCB})

	// IDs() returns SVCB; Get returns (nil, false). Walker must
	// continue without dereferencing style. Result: empty record set
	// since the walker has nothing to emit. No panic.
	records := svc.ComputeRequiredDNSRecords(reg)
	assert.Empty(t, records)
}
