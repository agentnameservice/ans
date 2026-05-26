package ans

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/domain"
)

func TestTLSARecord(t *testing.T) {
	mustReg := func(t *testing.T, host string, cert *domain.ByocServerCertificate) *domain.AgentRegistration {
		t.Helper()
		v, err := domain.NewSemVer(1, 0, 0)
		require.NoError(t, err)
		ansName, err := domain.NewAnsName(v, host)
		require.NoError(t, err)
		return &domain.AgentRegistration{AnsName: ansName, ServerCert: cert}
	}

	tests := []struct {
		name      string
		reg       *domain.AgentRegistration
		wantEmpty bool
		wantName  string
		wantValue string
	}{
		{
			name:      "no_server_cert_emits_no_tlsa",
			reg:       mustReg(t, "agent.example.com", nil),
			wantEmpty: true,
		},
		{
			name: "with_cert_emits_dane_ee_spki_sha256_record",
			reg: mustReg(t, "agent.example.com", &domain.ByocServerCertificate{
				Fingerprint: "abcdef0123456789",
			}),
			wantName:  "_443._tcp.agent.example.com",
			wantValue: "3 1 1 abcdef0123456789",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TLSARecord(tc.reg)
			if tc.wantEmpty {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			r := got[0]
			assert.Equal(t, tc.wantName, r.Name)
			assert.Equal(t, domain.DNSRecordTLSA, r.Type)
			assert.Equal(t, tc.wantValue, r.Value)
			assert.Equal(t, domain.PurposeCertificateBinding, r.Purpose)
			assert.False(t, r.Required, "TLSA is non-required because operator zones may not be DNSSEC-signed")
			assert.Equal(t, 3600, r.TTL)
		})
	}
}
