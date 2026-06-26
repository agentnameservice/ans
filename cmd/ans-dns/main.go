// Command ans-dns is a small authoritative DNS server + zone-management
// CLI for local-dev testing of the full ANS lifecycle end-to-end.
//
// Subcommands:
//
//	ans-dns serve   [--addr HOST:PORT] [--zone PATH]  [--dnssec]
//	ans-dns install <ra-url> <agent-id> [--api-key KEY] [--zone PATH]
//	ans-dns clear   <agent-id>                          [--zone PATH]
//
// `serve` runs a miekg/dns authoritative server backed by a JSON zone
// file on disk (reloaded on each request so `install`/`clear`
// subcommands take effect without a restart). With `--dnssec`, the
// server answers TLSA queries with the AD bit set so the RA's
// verifier surfaces DNSSECVerified=true on the resulting attestation.
// There is no chain-of-trust to any root; the DO bit is honored for
// completeness but signatures aren't validated against a parent zone.
//
// `install` fetches the RA's expected-records list for an agent and
// writes those records into the zone file. `clear` removes them.
//
// Not a production nameserver. No zone transfers, no NOTIFY, no
// secondary-server protocol. It exists so an operator can point
// their RA at `127.0.0.1:15353` and drive verify-dns from a local
// terminal.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "install":
		err = runInstall(args)
	case "clear":
		err = runClear(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ans-dns — local authoritative DNS server for ANS lifecycle testing

Usage:
  ans-dns serve   [--addr HOST:PORT] [--zone PATH] [--dnssec]
  ans-dns install <ra-url> <agent-id> [--api-key KEY] [--zone PATH]
  ans-dns clear   <agent-id> [--zone PATH]

Flags:
  --addr     Listen address for the DNS server (default 127.0.0.1:15353).
  --zone     Path to the JSON zone file (default ./data/ans-dns.zone.json).
  --dnssec   Reply with the AD bit so the RA verifier surfaces
             DNSSECVerified=true on TLSA attestations (dev-only).
  --api-key  Static API key for the RA; only needed if the RA requires it.
`)
}

// ----- zone file format (JSON for easy scripting) -----

type zoneFile struct {
	// Records are keyed by agentId so `install` / `clear` can touch
	// one agent's records at a time without clobbering another's.
	Records map[string][]zoneRecord `json:"records"`
}

type zoneRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

func loadZone(path string) (*zoneFile, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &zoneFile{Records: map[string][]zoneRecord{}}, nil
		}
		return nil, err
	}
	defer f.Close()
	var z zoneFile
	if err := json.NewDecoder(f).Decode(&z); err != nil {
		return nil, fmt.Errorf("parse zone: %w", err)
	}
	if z.Records == nil {
		z.Records = map[string][]zoneRecord{}
	}
	return &z, nil
}

func saveZone(path string, z *zoneFile) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(z); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// flatten returns every record across every agent.
func (z *zoneFile) flatten() []zoneRecord {
	var out []zoneRecord
	for _, recs := range z.Records {
		out = append(out, recs...)
	}
	return out
}

// ----- `serve` -----

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:15353", "listen address")
	zonePath := fs.String("zone", "./data/ans-dns.zone.json", "zone file path")
	authData := fs.Bool("dnssec", false, "set AD bit on replies (dev-only DNSSEC simulation)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		mu   sync.RWMutex
		zone *zoneFile
	)
	reload := func() error {
		z, err := loadZone(*zonePath)
		if err != nil {
			return err
		}
		mu.Lock()
		zone = z
		mu.Unlock()
		return nil
	}
	if err := reload(); err != nil {
		return err
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		// Reload zone on every request — keeps `install`/`clear`
		// effective without a restart, and the per-request cost is
		// negligible at dev-scale traffic.
		_ = reload()

		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.AuthenticatedData = *authData

		if len(req.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		mu.RLock()
		records := zone.flatten()
		mu.RUnlock()

		answers := answersFor(q, records)
		m.Answer = answers
		if len(answers) == 0 {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})

	// Run UDP + TCP in parallel; shut down on SIGINT/SIGTERM.
	udp := &dns.Server{Addr: *addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: *addr, Net: "tcp", Handler: mux}

	errs := make(chan error, 2)
	go func() { errs <- udp.ListenAndServe() }()
	go func() { errs <- tcp.ListenAndServe() }()

	fmt.Printf("ans-dns serving on %s (zone=%s, dnssec=%v)\n", *addr, *zonePath, *authData)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("shutting down")
	case err := <-errs:
		if err != nil {
			return err
		}
	}
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	return nil
}

// answersFor returns the RRs in `records` whose name + type match q.
// Comparison is case-insensitive on name; trailing dots normalized.
func answersFor(q dns.Question, records []zoneRecord) []dns.RR {
	wantName := strings.ToLower(dns.Fqdn(q.Name))
	wantType := dns.TypeToString[q.Qtype]
	var out []dns.RR
	for _, r := range records {
		if strings.ToLower(dns.Fqdn(r.Name)) != wantName {
			continue
		}
		if r.Type != wantType {
			continue
		}
		ttl := r.TTL
		if ttl <= 0 {
			ttl = 60
		}
		// Compose a zone-file line and parse it — lets us support
		// every type miekg/dns understands without enumerating.
		line := fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(r.Name), ttl, r.Type, formatZoneValue(r.Type, r.Value))
		rr, err := dns.NewRR(line)
		if err != nil {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// formatZoneValue massages the RR data into its zone-file
// presentation form. TXT values need quoting; others pass through.
func formatZoneValue(typ, val string) string {
	if typ == "TXT" {
		// Double quotes around the full value. Escape embedded quotes.
		return `"` + strings.ReplaceAll(val, `"`, `\"`) + `"`
	}
	return val
}

// ----- `install` -----

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	zonePath := fs.String("zone", "./data/ans-dns.zone.json", "zone file path")
	apiKey := fs.String("api-key", "", "RA API key (if required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("install: want <ra-url> <agent-id>, got %v", rest)
	}
	raURL, agentID := rest[0], rest[1]

	records, err := fetchAgentDNSRecords(context.Background(), raURL, agentID, *apiKey)
	if err != nil {
		return fmt.Errorf("fetch agent records: %w", err)
	}

	z, err := loadZone(*zonePath)
	if err != nil {
		return err
	}
	z.Records[agentID] = records
	if err := saveZone(*zonePath, z); err != nil {
		return err
	}
	fmt.Printf("installed %d records for %s into %s\n", len(records), agentID, *zonePath)
	return nil
}

// fetchAgentDNSRecords pulls the RA's expected-records list for an
// agent. Prefers the `registrationPending.dnsRecords` block on GET
// /v1/agents/{id} since that's the authoritative set for the agent's
// current status (challenges during PENDING_VALIDATION, production
// records during PENDING_DNS).
func fetchAgentDNSRecords(ctx context.Context, raURL, agentID, apiKey string) ([]zoneRecord, error) {
	url := strings.TrimRight(raURL, "/") + "/v1/agents/" + agentID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RA returned %d: %s", resp.StatusCode, body)
	}

	var detail struct {
		RegistrationPending *struct {
			DNSRecords []struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
				TTL   int    `json:"ttl"`
			} `json:"dnsRecords"`
		} `json:"registrationPending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	if detail.RegistrationPending == nil || len(detail.RegistrationPending.DNSRecords) == 0 {
		return nil, fmt.Errorf("agent %s has no pending DNS records (status may be ACTIVE or terminal)", agentID)
	}
	out := make([]zoneRecord, 0, len(detail.RegistrationPending.DNSRecords))
	for _, r := range detail.RegistrationPending.DNSRecords {
		out = append(out, zoneRecord{Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL})
	}
	return out, nil
}

// ----- `clear` -----

func runClear(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	zonePath := fs.String("zone", "./data/ans-dns.zone.json", "zone file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("clear: want <agent-id>, got %v", rest)
	}
	agentID := rest[0]
	z, err := loadZone(*zonePath)
	if err != nil {
		return err
	}
	n := len(z.Records[agentID])
	delete(z.Records, agentID)
	if err := saveZone(*zonePath, z); err != nil {
		return err
	}
	fmt.Printf("cleared %d records for %s from %s\n", n, agentID, *zonePath)
	return nil
}
