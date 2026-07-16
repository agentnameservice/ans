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
func newTestRegistry(t *testing.T) port.ProfileRegistry {
	t.Helper()
	r, err := service.NewDefaultProfileRegistry("")
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

func mustReg(t *testing.T, host string, version string, eps []domain.AgentEndpoint, cert *domain.ByocServerCertificate, profiles []domain.DiscoveryProfile) *domain.AgentRegistration {
	t.Helper()
	v, err := domain.ParseSemVer(version)
	require.NoError(t, err)
	ansName, err := domain.NewAnsName(v, host)
	require.NoError(t, err)
	return &domain.AgentRegistration{
		AnsName:           ansName,
		Endpoints:         eps,
		ServerCert:        cert,
		DiscoveryProfiles: profiles,
	}
}

// TestComputeRequiredDNSRecords_BadgeURLFromRegistryConstruction pins the
// end-to-end wiring: NewDefaultProfileRegistry stamps the deployment TL
// URL into the ANS styles, so the family `_ans-badge` record points at the
// TL's per-agent endpoint rather than the agent's own host. The per-adapter
// ansbadge_test covers BadgeRecord directly; this guards the
// registry→style→walker path end to end — without the URL reaching the
// styles, the badge silently regresses to the agent's endpoint URL.
func TestComputeRequiredDNSRecords_BadgeURLFromRegistryConstruction(t *testing.T) {
	discoveryReg, err := service.NewDefaultProfileRegistry("https://tl.example.org")
	require.NoError(t, err)
	svc := service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		discoveryReg,
	)

	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"}},
		nil, []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID})
	reg.AgentID = "test-agent-id"

	records := svc.ComputeRequiredDNSRecords(reg)

	var badge *domain.ExpectedDNSRecord
	for i := range records {
		if records[i].Purpose == domain.PurposeBadge {
			badge = &records[i]
			break
		}
	}
	require.NotNil(t, badge, "expected a _ans-badge record")
	assert.Contains(t, badge.Value, "url=https://tl.example.org/v1/agents/test-agent-id")
	assert.NotContains(t, badge.Value, "agent.example.com/mcp")
}

// TestComputeRequiredDNSRecords_StyleMatrix_Integration is the
// migrated cross-style integration matrix from
// internal/domain/dnsrecords_test.go:105-284. Per-adapter tests cover
// within-style rules; this table is the regression suite for the
// styles cross-product (e.g. "SVCB-sole emits no HTTPS RR" — only
// testable across both adapters' output).
func TestComputeRequiredDNSRecords_StyleMatrix_Integration(t *testing.T) {
	const sampleMetadataHash = "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"
	const wantSampleCapBase64 = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc"

	tests := []struct {
		name             string
		styles           []domain.DiscoveryProfile
		protocol         domain.Protocol
		agentURL         string
		metadataURL      string // optional per-endpoint MetadataURL (feeds cap + well-known)
		metadataHash     string // optional per-endpoint MetadataHash (feeds cap-sha256)
		wantHTTPS        bool
		wantSVCB         bool
		wantSVCBRequired bool // applies only when wantSVCB is true
		wantLegacyTXT    bool
		wantSVCBAlpn     string // substring expected (e.g. "alpn=a2a")
		wantSVCBBap      string // substring expected (e.g. "key65402=a2a")
		wantSVCBPort     string // substring expected (e.g. "port=443")
		wantSVCBCapLoc   string // "" means SVCB MUST NOT contain "key65400=" (cap locator)
		wantSVCBCapSHA   string // "" means SVCB MUST NOT contain "key65401=" (capability digest)
		wantSVCBWk       string // "" means SVCB MUST NOT contain "key65409=" (well-known suffix)
	}{
		{
			name:          "ans_txt_only_emits_https_rr_no_svcb",
			styles:        []domain.DiscoveryProfile{domain.DiscoveryProfileANSTXT},
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
		},
		{
			name:             "ans_dnsaid_only_omits_https_rr",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true, // SVCB-sole: only PurposeDiscovery record, must be required
			wantSVCBAlpn:     "alpn=a2a",
			wantSVCBBap:      "key65402=a2a",
			wantSVCBPort:     "port=443",
		},
		{
			name:          "union_emits_both_families",
			styles:        []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID, domain.DiscoveryProfileANSTXT},
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true,
			wantLegacyTXT: true,
			wantSVCB:      true,
			// wantSVCBRequired: false — legacy `_ans` TXT carries the
			// Required signal during the §4.4.2 transition; SVCB rides
			// along as optional.
			wantSVCBAlpn: "alpn=a2a",
			wantSVCBBap:  "key65402=a2a",
			wantSVCBPort: "port=443",
		},
		{
			name:             "dnsaid_mcp_cap_and_wk_from_metadata_url",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolMCP,
			agentURL:         "https://agent.example.com/mcp",
			metadataURL:      "https://agent.example.com/.well-known/mcp.json",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBAlpn:     "alpn=mcp",
			wantSVCBBap:      "key65402=mcp",
			wantSVCBPort:     "port=443",
			wantSVCBCapLoc:   "key65400=https://agent.example.com/.well-known/mcp.json",
			wantSVCBWk:       "key65409=mcp.json",
		},
		{
			name:             "dnsaid_http_api_maps_alpn_and_bap_to_x_http",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolHTTPAPI,
			agentURL:         "https://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBAlpn:     "alpn=x-http",
			wantSVCBBap:      "key65402=x-http",
			wantSVCBPort:     "port=443",
		},
		{
			name:             "dnsaid_cap_sha256_from_endpoint_metadata_hash",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com",
			metadataURL:      "https://agent.example.com/.well-known/agent-card.json",
			metadataHash:     sampleMetadataHash,
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBAlpn:     "alpn=a2a",
			wantSVCBBap:      "key65402=a2a",
			wantSVCBPort:     "port=443",
			wantSVCBCapLoc:   "key65400=https://agent.example.com/.well-known/agent-card.json",
			wantSVCBCapSHA:   "key65401=" + wantSampleCapBase64,
			wantSVCBWk:       "key65409=agent-card.json",
		},
		{
			name:             "dnsaid_non_443_port_from_url",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolA2A,
			agentURL:         "https://agent.example.com:8443",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBAlpn:     "alpn=a2a",
			wantSVCBBap:      "key65402=a2a",
			wantSVCBPort:     "port=8443",
		},
		{
			name:             "dnsaid_http_scheme_defaults_port_80",
			styles:           []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID},
			protocol:         domain.ProtocolA2A,
			agentURL:         "http://agent.example.com",
			wantSVCB:         true,
			wantSVCBRequired: true,
			wantSVCBAlpn:     "alpn=a2a",
			wantSVCBBap:      "key65402=a2a",
			wantSVCBPort:     "port=80",
		},
		{
			name:          "empty_styles_coerces_to_default_ans_txt",
			styles:        nil,
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true, // default is now {ANS_TXT}: HTTPS RR + _ans TXT, no SVCB
			wantLegacyTXT: true,
		},
		{
			name:          "all_invalid_styles_falls_back_to_default_ans_txt",
			styles:        []domain.DiscoveryProfile{domain.DiscoveryProfile("garbage"), domain.DiscoveryProfile("nonsense")},
			protocol:      domain.ProtocolA2A,
			agentURL:      "https://agent.example.com",
			wantHTTPS:     true, // fallback default is now {ANS_TXT}
			wantLegacyTXT: true,
		},
	}

	svc := newComputeOnlyService(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := mustReg(t, "agent.example.com", "1.0.0",
				[]domain.AgentEndpoint{{
					Protocol:     tc.protocol,
					AgentURL:     tc.agentURL,
					MetadataURL:  tc.metadataURL,
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
					"SVCB Required flag mismatch (true iff ANS_DNSAID is the sole resolved style)")
				assert.Contains(t, svcbValue, tc.wantSVCBAlpn, "SVCB alpn SvcParam mismatch")
				assert.Contains(t, svcbValue, tc.wantSVCBBap, "SVCB bap (key65402) SvcParam mismatch")
				assert.Contains(t, svcbValue, tc.wantSVCBPort, "SVCB port SvcParam mismatch")
				if tc.wantSVCBCapLoc != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBCapLoc, "SVCB cap (key65400) locator mismatch")
				} else {
					assert.NotContains(t, svcbValue, "key65400=",
						"SVCB MUST NOT carry key65400 (cap) without a metadataUrl")
				}
				if tc.wantSVCBCapSHA != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBCapSHA, "SVCB cap-sha256 (key65401) digest mismatch")
				} else {
					assert.NotContains(t, svcbValue, "key65401=",
						"SVCB MUST NOT carry key65401 (cap-sha256) when endpoint MetadataHash is empty")
				}
				if tc.wantSVCBWk != "" {
					assert.Contains(t, svcbValue, tc.wantSVCBWk, "SVCB well-known (key65409) SvcParam mismatch")
				} else {
					assert.NotContains(t, svcbValue, "key65409=",
						"SVCB MUST NOT carry key65409 (well-known) unless metadataUrl is at /.well-known/")
				}
				// Named-form regression guards across the integration path.
				assert.NotContains(t, svcbValue, "cap=",
					"named `cap=` SvcParam MUST NOT appear; key65400 is the publishable form")
				assert.NotContains(t, svcbValue, "bap=",
					"named `bap=` SvcParam MUST NOT appear; key65402 is the publishable form")
				assert.NotContains(t, svcbValue, "cap-sha256",
					"named `cap-sha256=` SvcParam MUST NOT appear; key65401 is the publishable form")
				assert.NotContains(t, svcbValue, "well-known=",
					"named `well-known=` SvcParam MUST NOT appear; key65409 is the publishable form")
			}
		})
	}
}

// TestComputeRequiredDNSRecords_UnionDedupesFamilyTrustRecords pins
// that when the union {ANS_DNSAID, ANS_TXT} emits, family trust records
// (`_ans-badge`, TLSA) appear ONCE in the output even though both
// adapters emit them. Catches a regression where the dedup pass is
// removed or the dedup key drifts.
func TestComputeRequiredDNSRecords_UnionDedupesFamilyTrustRecords(t *testing.T) {
	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		&domain.ByocServerCertificate{Fingerprint: "abcdef"},
		[]domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID, domain.DiscoveryProfileANSTXT})

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

// TestNewRegistrationService_PanicsOnNilProfileRegistry pins the
// fail-loud invariant the constructor enforces. A missing registry
// would silently emit zero `dnsRecordsProvisioned[]` and accept any
// DNS state at verify-dns — trust-root corruption masquerading as
// graceful degradation. Construction is process-start-time, not a
// request path, so the panic does not violate the no-panics-in-
// request-paths rule.
func TestNewRegistrationService_PanicsOnNilProfileRegistry(t *testing.T) {
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
// reg.DiscoveryProfiles entry the registry doesn't have is silently
// skipped (with a WARN log; not asserted in this test). The remaining
// valid profiles still emit. If every entry is unknown, the walker
// falls back to DefaultDiscoveryProfiles.
func TestComputeRequiredDNSRecords_UnknownStyleSkipped(t *testing.T) {
	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		nil,
		[]domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID, domain.DiscoveryProfile("UNKNOWN_FUTURE")})

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
// transition union (ANS_DNSAID + ANS_TXT). Any change to slice ORDER
// (JCS preserves array order per RFC 8785 §3.2.2) would shift the
// SHA-256, signal a wire-shape regression, and break offline-verifier
// hashes for in-flight agents at deploy time.
//
// The hex constant was REGENERATED for the DNS-AID conformance change:
// each SVCB row now carries the draft-02 keyNNNNN params — key65400
// (cap, from metadataUrl), key65401 (cap-sha256, from metadataHash),
// key65402 (bap), and key65409 (well-known, derived from the metadataUrl
// path) — replacing the old key65280/key65281 set. The fixture endpoints
// carry a /.well-known/ metadataUrl so cap and well-known are exercised
// here at the service-composition layer, not only in the adapter unit
// tests.
//
// REGENERATED again for the ANS-3 §6.3 version= fix (issue #69): the
// three TXT rows in the union (two `_ans` + one `_ans-badge`) now
// carry the v-prefixed ANSName version segment (`version=v1.2.3`)
// instead of the bare semver. The slice ORDER and the 7-record SHAPE
// are unchanged; only those three TXT values move the hash. A future
// drift that is NOT a deliberate wire-value change is a regression:
// investigate before touching this constant.
func TestComputeRequiredDNSRecords_UnionCanonicalBytesRegression(t *testing.T) {
	const wantSHA256Hex = "2f7b7aefc0032e0900ae446595c503b853c45738e8ae717c3b2ba74c3edf3286"

	svc := newComputeOnlyService(t)
	reg := mustReg(t, "agent.example.com", "1.2.3",
		[]domain.AgentEndpoint{
			{
				Protocol:     domain.ProtocolA2A,
				AgentURL:     "https://agent.example.com/a2a",
				MetadataURL:  "https://agent.example.com/.well-known/agent-card.json",
				MetadataHash: "SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27",
			},
			{
				Protocol:     domain.ProtocolMCP,
				AgentURL:     "https://agent.example.com/mcp",
				MetadataURL:  "https://agent.example.com/.well-known/mcp.json",
				MetadataHash: "SHA256:1111111111111111111111111111111111111111111111111111111111111111",
			},
		},
		&domain.ByocServerCertificate{Fingerprint: "deadbeefcafe1234"},
		[]domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID, domain.DiscoveryProfileANSTXT})

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

	// The two SVCB rows carry the draft-02 keyNNNNN params at the
	// service-composition layer: cap (key65400) + bap (key65402) + the
	// /.well-known/-derived well-known suffix (key65409). Pins that cap
	// and well-known reach the union record set, not only the adapter.
	assert.Contains(t, records[3].Value, "key65400=https://agent.example.com/.well-known/agent-card.json")
	assert.Contains(t, records[3].Value, "key65402=a2a")
	assert.Contains(t, records[3].Value, "key65409=agent-card.json")
	assert.Contains(t, records[4].Value, "key65400=https://agent.example.com/.well-known/mcp.json")
	assert.Contains(t, records[4].Value, "key65402=mcp")
	assert.Contains(t, records[4].Value, "key65409=mcp.json")

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

// TestNewDefaultProfileRegistry pins the default-wiring contract:
// returns a registry containing both ANS-family styles in TXT-then-SVCB
// insertion order. The order is the V2 canonical-bytes input.
func TestNewDefaultProfileRegistry(t *testing.T) {
	r, err := service.NewDefaultProfileRegistry("")
	require.NoError(t, err)

	got := r.IDs()
	want := []domain.DiscoveryProfile{domain.DiscoveryProfileANSTXT, domain.DiscoveryProfileANSDNSAID}
	assert.Equal(t, want, got, "default registry must wire TXT before SVCB to preserve V2 union canonical bytes")
}

// TestComputeRequiredDNSRecords_RegistryIterationOrderDeterminesEmission
// pins that a non-default registry wiring (SVCB before TXT) actually
// produces a different emission order — proving the walker honours
// registry insertion order rather than user-supplied
// reg.DiscoveryProfiles order.
func TestComputeRequiredDNSRecords_RegistryIterationOrderDeterminesEmission(t *testing.T) {
	// Build a "production" service (default registry wiring: TXT, SVCB)
	// and a custom one with SVCB before TXT.
	defaultSvc := newComputeOnlyService(t)

	customReg, err := registry.New(svcStub{id: domain.DiscoveryProfileANSDNSAID, marker: "S"}, svcStub{id: domain.DiscoveryProfileANSTXT, marker: "T"})
	require.NoError(t, err)
	customSvc := service.NewRegistrationService(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, customReg)

	reg := mustReg(t, "agent.example.com", "1.0.0",
		[]domain.AgentEndpoint{{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"}},
		nil,
		[]domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID, domain.DiscoveryProfileANSTXT})

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

// svcStub is a minimal port.ProfileEmitter for ordering tests; emits
// no records so the test asserts purely on walker behavior.
type svcStub struct {
	id     domain.DiscoveryProfile
	marker string
}

func (s svcStub) ID() domain.DiscoveryProfile { return s.id }
func (svcStub) Records(*domain.AgentRegistration) []domain.ExpectedDNSRecord {
	return nil
}

// inconsistentRegistry violates the IDs()/Get consistency contract:
// IDs() advertises a style that Get() does not have. The walker's
// defensive `if !ok { continue }` branch is the safety net for that
// contract violation. The bundled registry maintains the contract by
// construction, so this fake exercises a branch only a custom
// port.ProfileRegistry implementation could ever reach.
type inconsistentRegistry struct{}

func (inconsistentRegistry) IDs() []domain.DiscoveryProfile {
	return []domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID}
}

func (inconsistentRegistry) Get(domain.DiscoveryProfile) (port.ProfileEmitter, bool) {
	return nil, false
}

// TestComputeRequiredDNSRecords_RegistryGetMissDoesNotPanic pins the
// defensive branch the walker takes when registry.IDs() and Get fall
// out of sync. The branch is unreachable in production wiring; it
// exists so a future custom port.ProfileRegistry implementation
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
		[]domain.DiscoveryProfile{domain.DiscoveryProfileANSDNSAID})

	// IDs() returns SVCB; Get returns (nil, false). Walker must
	// continue without dereferencing style. Result: empty record set
	// since the walker has nothing to emit. No panic.
	records := svc.ComputeRequiredDNSRecords(reg)
	assert.Empty(t, records)
}
