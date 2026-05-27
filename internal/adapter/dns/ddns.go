package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/miekg/dns"
)

// DDNSProvisioner implements port.DNSProvisioner via RFC 2136 dynamic
// DNS updates with TSIG authentication.
type DDNSProvisioner struct {
	server        string
	zone          string
	tsigName      string
	tsigSecret    string
	tsigAlgorithm string
	timeout       time.Duration
}

type DDNSOption func(*DDNSProvisioner)

func WithDDNSServer(addr string) DDNSOption {
	return func(p *DDNSProvisioner) { p.server = addr }
}

func WithDDNSZone(zone string) DDNSOption {
	return func(p *DDNSProvisioner) { p.zone = dns.Fqdn(zone) }
}

func WithTSIG(name, secret, algorithm string) DDNSOption {
	return func(p *DDNSProvisioner) {
		p.tsigName = dns.Fqdn(name)
		p.tsigSecret = secret
		if algorithm != "" {
			p.tsigAlgorithm = dns.Fqdn(algorithm)
		}
	}
}

func WithDDNSTimeout(d time.Duration) DDNSOption {
	return func(p *DDNSProvisioner) { p.timeout = d }
}

func NewDDNSProvisioner(opts ...DDNSOption) *DDNSProvisioner {
	p := &DDNSProvisioner{
		tsigAlgorithm: dns.HmacSHA256,
		timeout:       5 * time.Second,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *DDNSProvisioner) ProvisionRecords(ctx context.Context, _ string, records []domain.ExpectedDNSRecord) error {
	if len(records) == 0 {
		return nil
	}

	msg := new(dns.Msg)
	msg.SetUpdate(p.zone)

	for _, rec := range records {
		rrs, err := p.toRR(rec)
		if err != nil {
			return fmt.Errorf("build RR for %s %s: %w", rec.Name, rec.Type, err)
		}
		// Remove-then-insert gives replace semantics (idempotent).
		msg.RemoveRRset(rrs)
		msg.Insert(rrs)
	}

	return p.exchange(ctx, msg)
}

func (p *DDNSProvisioner) DeleteRecords(ctx context.Context, _ string, records []domain.ExpectedDNSRecord) error {
	if len(records) == 0 {
		return nil
	}

	msg := new(dns.Msg)
	msg.SetUpdate(p.zone)

	for _, rec := range records {
		rrs, err := p.toRR(rec)
		if err != nil {
			return fmt.Errorf("build RR for %s %s: %w", rec.Name, rec.Type, err)
		}
		msg.RemoveRRset(rrs)
	}

	return p.exchange(ctx, msg)
}

func (p *DDNSProvisioner) exchange(ctx context.Context, msg *dns.Msg) error {
	client := new(dns.Client)
	client.Timeout = p.timeout

	if p.tsigName != "" && p.tsigSecret != "" {
		client.TsigSecret = map[string]string{p.tsigName: p.tsigSecret}
		msg.SetTsig(p.tsigName, p.tsigAlgorithm, 300, time.Now().Unix())
	}

	resp, _, err := client.ExchangeContext(ctx, msg, p.server)
	if err != nil {
		return fmt.Errorf("dns update exchange: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns update failed: %s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func (p *DDNSProvisioner) toRR(rec domain.ExpectedDNSRecord) ([]dns.RR, error) {
	name := dns.Fqdn(rec.Name)
	ttl := uint32(3600)
	if rec.TTL > 0 && rec.TTL <= math.MaxUint32 {
		ttl = uint32(rec.TTL)
	}

	switch rec.Type {
	case domain.DNSRecordTXT:
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: splitTXT(rec.Value),
		}
		return []dns.RR{rr}, nil

	case domain.DNSRecordTLSA:
		tlsa, err := parseTLSA(rec.Value)
		if err != nil {
			return nil, err
		}
		tlsa.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: ttl}
		return []dns.RR{tlsa}, nil

	case domain.DNSRecordSVCB:
		svcb, err := parseSVCBValue(rec.Value)
		if err != nil {
			return nil, err
		}
		svcb.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: ttl}
		return []dns.RR{svcb}, nil

	case domain.DNSRecordHTTPS:
		return nil, errors.New("HTTPS record provisioning not supported")

	default:
		return nil, fmt.Errorf("unsupported record type: %s", rec.Type)
	}
}

// splitTXT splits a TXT value into 255-byte chunks per RFC 1035 §3.3.14.
func splitTXT(val string) []string {
	if len(val) <= 255 {
		return []string{val}
	}
	var chunks []string
	for len(val) > 0 {
		end := 255
		if end > len(val) {
			end = len(val)
		}
		chunks = append(chunks, val[:end])
		val = val[end:]
	}
	return chunks
}

// parseTLSA parses "usage selector mtype hex" into a dns.TLSA RR.
func parseTLSA(val string) (*dns.TLSA, error) {
	parts := strings.Fields(val)
	if len(parts) != 4 {
		return nil, fmt.Errorf("TLSA value must have 4 fields, got %d: %q", len(parts), val)
	}
	usage, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("TLSA usage: %w", err)
	}
	selector, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("TLSA selector: %w", err)
	}
	matchingType, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("TLSA matching type: %w", err)
	}
	return &dns.TLSA{
		Usage:        uint8(usage),
		Selector:     uint8(selector),
		MatchingType: uint8(matchingType),
		Certificate:  strings.ToLower(parts[3]),
	}, nil
}

// parseSVCBValue parses "priority target key=val ..." into a dns.SVCB RR.
func parseSVCBValue(val string) (*dns.SVCB, error) {
	parts := strings.Fields(val)
	if len(parts) < 2 {
		return nil, fmt.Errorf("SVCB value must have at least priority and target, got: %q", val)
	}

	priority, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SVCB priority: %w", err)
	}

	target := parts[1]

	var params []dns.SVCBKeyValue
	for _, kv := range parts[2:] {
		eqIdx := strings.IndexByte(kv, '=')
		if eqIdx < 0 {
			continue
		}
		key, value := kv[:eqIdx], kv[eqIdx+1:]
		switch key {
		case "alpn":
			params = append(params, &dns.SVCBAlpn{Alpn: strings.Split(value, ",")})
		case "port":
			p, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("SVCB port: %w", err)
			}
			params = append(params, &dns.SVCBPort{Port: uint16(p)})
		}
	}

	return &dns.SVCB{
		Priority: uint16(priority),
		Target:   target,
		Value:    params,
	}, nil
}
