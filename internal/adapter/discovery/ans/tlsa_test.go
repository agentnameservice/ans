package ans

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
)

func TestTLSARecord(t *testing.T) {
	mustRegWithEndpoints := func(t *testing.T, host string, eps []domain.AgentEndpoint, cert *domain.ByocServerCertificate) *domain.AgentRegistration {
		t.Helper()
		v, err := domain.NewSemVer(1, 0, 0)
		require.NoError(t, err)
		ansName, err := domain.NewAnsName(v, host)
		require.NoError(t, err)
		return &domain.AgentRegistration{AnsName: ansName, Endpoints: eps, ServerCert: cert}
	}

	const fp = "abcdef0123456789"

	tests := []struct {
		name      string
		reg       *domain.AgentRegistration
		wantEmpty bool
		// wantNamesInOrder is the exact sequence of TLSA owner names the
		// record set must contain, in order. Ports are sorted numerically
		// ascending, so this also pins the sort.
		wantNamesInOrder []string
		wantValue        string // applied to every emitted record
	}{
		{
			name:      "no_server_cert_emits_no_tlsa",
			reg:       mustRegWithEndpoints(t, "agent.example.com", nil, nil),
			wantEmpty: true,
		},
		{
			// 443 fallback: ServerCert set but no endpoints carry a port.
			// Exactly one record at _443._tcp.
			name: "no_endpoints_falls_back_to_443",
			reg: mustRegWithEndpoints(t, "agent.example.com", nil,
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{"_443._tcp.agent.example.com"},
			wantValue:        "3 0 1 " + fp,
		},
		{
			name: "single_https_non_443_port",
			reg: mustRegWithEndpoints(t, "agent.example.com",
				[]domain.AgentEndpoint{
					{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com:8443"},
				},
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{"_8443._tcp.agent.example.com"},
			wantValue:        "3 0 1 " + fp,
		},
		{
			// Numeric-not-lexical sort + dedupe. Ports 443 and 1024 sort
			// 443 < 1024 numerically, but "_1024" < "_443" lexically
			// (since '1' < '4'). The output MUST be _443 then _1024,
			// proving the sort is by int, not by string.
			name: "two_ports_443_and_1024_sort_numerically",
			reg: mustRegWithEndpoints(t, "agent.example.com",
				[]domain.AgentEndpoint{
					{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com:443"},
					{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com:1024"},
				},
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{
				"_443._tcp.agent.example.com",
				"_1024._tcp.agent.example.com",
			},
			wantValue: "3 0 1 " + fp,
		},
		{
			// Duplicate ports across endpoints collapse to one record.
			name: "duplicate_ports_deduped",
			reg: mustRegWithEndpoints(t, "agent.example.com",
				[]domain.AgentEndpoint{
					{Protocol: domain.ProtocolA2A, AgentURL: "https://agent.example.com"},
					{Protocol: domain.ProtocolMCP, AgentURL: "https://agent.example.com/mcp"},
				},
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{"_443._tcp.agent.example.com"},
			wantValue:        "3 0 1 " + fp,
		},
		{
			// All-plaintext (http) endpoints + ServerCert set. The cert
			// binding still needs a home, so the 443 fallback fires:
			// exactly one record at _443._tcp.
			name: "all_plaintext_endpoints_with_cert_falls_back_to_443",
			reg: mustRegWithEndpoints(t, "agent.example.com",
				[]domain.AgentEndpoint{
					{Protocol: domain.ProtocolA2A, AgentURL: "http://agent.example.com"},
					{Protocol: domain.ProtocolMCP, AgentURL: "http://agent.example.com:8080"},
				},
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{"_443._tcp.agent.example.com"},
			wantValue:        "3 0 1 " + fp,
		},
		{
			// Boundary URLs: empty and unparseable AgentURLs are treated
			// as TLS (not plaintext http), so they take svcbPortFor's
			// default-443 path. Both collapse to one _443._tcp record. A
			// TLSA for an endpoint we can't fully parse is harmless
			// (Required=false); dropping one would silently lose a cert
			// binding.
			name: "empty_and_malformed_urls_treated_as_tls_default_443",
			reg: mustRegWithEndpoints(t, "agent.example.com",
				[]domain.AgentEndpoint{
					{Protocol: domain.ProtocolA2A, AgentURL: ""},
					{Protocol: domain.ProtocolMCP, AgentURL: "://not-a-url"},
				},
				&domain.ByocServerCertificate{Fingerprint: fp}),
			wantNamesInOrder: []string{"_443._tcp.agent.example.com"},
			wantValue:        "3 0 1 " + fp,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TLSARecord(tc.reg)
			if tc.wantEmpty {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, len(tc.wantNamesInOrder),
				"TLSA record count mismatch")
			for i, r := range got {
				assert.Equal(t, tc.wantNamesInOrder[i], r.Name,
					"TLSA owner name / sort order mismatch at index %d", i)
				assert.Equal(t, domain.DNSRecordTLSA, r.Type)
				assert.Equal(t, tc.wantValue, r.Value,
					"TLSA value must be `3 0 1 <full-cert SHA-256>` (DANE-EE, selector 0)")
				assert.Equal(t, domain.PurposeCertificateBinding, r.Purpose)
				assert.False(t, r.Required,
					"TLSA is non-required because operator zones may not be DNSSEC-signed")
				assert.Equal(t, 3600, r.TTL)
			}
		})
	}
}
