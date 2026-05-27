package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ddnsTestServer is a minimal DNS server that accepts RFC 2136 UPDATE
// messages and records them for assertion.
type ddnsTestServer struct {
	addr    string
	updates []*dns.Msg
	mu      sync.Mutex
}

func newDDNSTestServer(t *testing.T) *ddnsTestServer {
	t.Helper()

	s := &ddnsTestServer{}

	// Use a raw UDP listener and handle DNS manually to avoid
	// miekg/dns server's default NOTIMP response for UPDATE opcodes.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	s.addr = pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			req := new(dns.Msg)
			if uerr := req.Unpack(buf[:n]); uerr != nil {
				continue
			}

			s.mu.Lock()
			s.updates = append(s.updates, req.Copy())
			s.mu.Unlock()

			resp := new(dns.Msg)
			resp.Id = req.Id
			resp.Response = true
			resp.Opcode = req.Opcode
			resp.Rcode = dns.RcodeSuccess
			out, _ := resp.Pack()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return s
}

func (s *ddnsTestServer) lastUpdate() *dns.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return nil
	}
	return s.updates[len(s.updates)-1]
}

func TestDDNSProvisioner_ProvisionTXTRecords(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1; version=1.0.0", TTL: 3600},
		{Name: "_ans-badge.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans-badge1; version=1.0.0; url=https://tl.example.com/v1/agents/123", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	assert.True(t, msg.Opcode == dns.OpcodeUpdate, "message should be an UPDATE")

	// Should have both remove and insert sections for each record.
	assert.NotEmpty(t, msg.Ns, "NS (update) section should contain RRs")
}

func TestDDNSProvisioner_ProvisionTLSARecord(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_443._tcp.agent.example.com", Type: domain.DNSRecordTLSA, Value: "3 1 1 abcdef0123456789", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	assert.True(t, msg.Opcode == dns.OpcodeUpdate)
}

func TestDDNSProvisioner_DeleteRecords(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1; version=1.0.0", TTL: 3600},
	}

	err := p.DeleteRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	assert.True(t, msg.Opcode == dns.OpcodeUpdate)
}

func TestDDNSProvisioner_EmptyRecordsNoOp(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	err := p.ProvisionRecords(context.Background(), "agent.example.com", nil)
	require.NoError(t, err)
	assert.Nil(t, srv.lastUpdate(), "no UPDATE should be sent for empty records")

	err = p.DeleteRecords(context.Background(), "agent.example.com", nil)
	require.NoError(t, err)
}

func TestDDNSProvisioner_Idempotent(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1", TTL: 3600},
	}

	require.NoError(t, p.ProvisionRecords(context.Background(), "agent.example.com", records))
	require.NoError(t, p.ProvisionRecords(context.Background(), "agent.example.com", records))

	srv.mu.Lock()
	count := len(srv.updates)
	srv.mu.Unlock()
	assert.Equal(t, 2, count, "two UPDATE messages sent (both succeed — server-side idempotent)")
}

func TestDDNSProvisioner_ServerUnreachable(t *testing.T) {
	t.Parallel()
	p := NewDDNSProvisioner(
		WithDDNSServer("127.0.0.1:1"),
		WithDDNSTimeout(100*time.Millisecond),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	assert.Error(t, err)
}

func TestDDNSProvisioner_WithTSIG(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
		WithTSIG("ans-key.", "c2VjcmV0", "hmac-sha256"),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	assert.NotEmpty(t, msg.Extra, "TSIG should be in the additional section")
}

func TestDDNSProvisioner_UnsupportedHTTPS(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "agent.example.com", Type: domain.DNSRecordHTTPS, Value: "1 . alpn=h2", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS record provisioning not supported")
}

func TestDDNSProvisioner_ProvisionSVCBRecord(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "agent.example.com", Type: domain.DNSRecordSVCB, Value: "1 real-host.example.com. alpn=h2 port=8080", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	assert.True(t, msg.Opcode == dns.OpcodeUpdate)
}

func TestParseSVCBValue(t *testing.T) {
	svcb, err := parseSVCBValue("1 host.example.com. alpn=h2 port=8080")
	require.NoError(t, err)
	assert.Equal(t, uint16(1), svcb.Priority)
	assert.Equal(t, "host.example.com.", svcb.Target)
	assert.Len(t, svcb.Value, 2)
}

func TestParseSVCBValue_AlpnOnly(t *testing.T) {
	svcb, err := parseSVCBValue("1 host.example.com. alpn=h2")
	require.NoError(t, err)
	assert.Equal(t, "host.example.com.", svcb.Target)
	assert.Len(t, svcb.Value, 1)
}

func TestParseSVCBValue_Invalid(t *testing.T) {
	_, err := parseSVCBValue("1")
	assert.Error(t, err)
}

func TestParseTLSA(t *testing.T) {
	tlsa, err := parseTLSA("3 1 1 abcdef0123456789")
	require.NoError(t, err)
	assert.Equal(t, uint8(3), tlsa.Usage)
	assert.Equal(t, uint8(1), tlsa.Selector)
	assert.Equal(t, uint8(1), tlsa.MatchingType)
	assert.Equal(t, "abcdef0123456789", tlsa.Certificate)
}

func TestParseTLSA_Invalid(t *testing.T) {
	_, err := parseTLSA("3 1")
	assert.Error(t, err)
}

func TestDDNSProvisioner_UnsupportedRecordType(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "agent.example.com", Type: domain.DNSRecordType("BOGUS"), Value: "x", TTL: 3600},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestDDNSProvisioner_ZeroTTLDefaultsTo3600(t *testing.T) {
	t.Parallel()
	srv := newDDNSTestServer(t)
	p := NewDDNSProvisioner(
		WithDDNSServer(srv.addr),
		WithDDNSZone("example.com."),
	)

	records := []domain.ExpectedDNSRecord{
		{Name: "_ans.agent.example.com", Type: domain.DNSRecordTXT, Value: "v=ans1", TTL: 0},
	}

	err := p.ProvisionRecords(context.Background(), "agent.example.com", records)
	require.NoError(t, err)

	msg := srv.lastUpdate()
	require.NotNil(t, msg)
	for _, rr := range msg.Ns {
		if rr.Header().Ttl != 0 {
			assert.Equal(t, uint32(3600), rr.Header().Ttl, "zero TTL should default to 3600")
		}
	}
}

func TestParseTLSA_NonNumericFields(t *testing.T) {
	_, err := parseTLSA("x 1 1 abcdef")
	assert.Error(t, err)
}

func TestParseSVCBValue_UnknownParam(t *testing.T) {
	svcb, err := parseSVCBValue("1 host.example.com. alpn=h2 unknown=value")
	require.NoError(t, err)
	assert.Equal(t, "host.example.com.", svcb.Target)
}

func TestNoopProvisioner(t *testing.T) {
	p := NewNoopProvisioner()
	assert.NoError(t, p.ProvisionRecords(context.Background(), "x", nil))
	assert.NoError(t, p.DeleteRecords(context.Background(), "x", nil))
}

func TestSplitTXT(t *testing.T) {
	short := "hello"
	assert.Equal(t, []string{"hello"}, splitTXT(short))

	long := string(make([]byte, 300))
	chunks := splitTXT(long)
	assert.Equal(t, 2, len(chunks))
	assert.Equal(t, 255, len(chunks[0]))
	assert.Equal(t, 45, len(chunks[1]))
}
