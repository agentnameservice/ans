package catalog

import "testing"

func TestValidateEmittedURL(t *testing.T) {
	const host = "ai-agent.acmecorp.com"

	tests := []struct {
		name          string
		raw           string
		host          string
		allowInsecure bool
		wantOK        bool
	}{
		{"valid https same host", "https://ai-agent.acmecorp.com/.well-known/agent-card.json", host, false, true},
		{"valid https with path and port", "https://ai-agent.acmecorp.com:8443/card.json", host, false, true},
		{"host match is case-insensitive", "https://AI-Agent.AcmeCorp.com/card.json", host, false, true},
		{"http rejected without override", "http://ai-agent.acmecorp.com/card.json", host, false, false},
		{"http allowed with override", "http://ai-agent.acmecorp.com/card.json", host, true, true},
		{"non-http(s) scheme rejected", "ftp://ai-agent.acmecorp.com/card.json", host, true, false},
		{"relative URL rejected", "/.well-known/agent-card.json", host, false, false},
		{"userinfo rejected", "https://user:pass@ai-agent.acmecorp.com/card.json", host, false, false},
		{"query rejected", "https://ai-agent.acmecorp.com/card.json?v=1", host, false, false},
		{"force-query (trailing ?) rejected", "https://ai-agent.acmecorp.com/card.json?", host, false, false},
		{"fragment rejected", "https://ai-agent.acmecorp.com/card.json#frag", host, false, false},
		{"cross-host rejected", "https://evil.example.net/card.json", host, false, false},
		{"empty host in URL rejected", "https:///card.json", host, false, false},
		{"empty raw rejected", "", host, false, false},
		{"empty agentHost rejected", "https://ai-agent.acmecorp.com/card.json", "", false, false},
		{"unparseable URL rejected", "https://ho\x00st/card.json", host, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := validateEmittedURL(tc.raw, tc.host, tc.allowInsecure)
			if ok != tc.wantOK {
				t.Fatalf("validateEmittedURL(%q,%q,%v) ok = %v, want %v", tc.raw, tc.host, tc.allowInsecure, ok, tc.wantOK)
			}
			if ok && got != tc.raw {
				t.Errorf("a passing URL must be emitted verbatim: got %q, want %q", got, tc.raw)
			}
			if !ok && got != "" {
				t.Errorf("a failing URL must return empty string, got %q", got)
			}
		})
	}
}
