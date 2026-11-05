package domain

import "testing"

func TestParseAttestedExpiry(t *testing.T) {
	empty, err := ParseAttestedExpiry("")
	if err != nil || !empty.IsZero() {
		t.Fatal("missing legacy expiry rejected")
	}
	valid, err := ParseAttestedExpiry("2030-01-01T00:00:00Z")
	if err != nil || valid.Year() != 2030 {
		t.Fatal("valid expiry rejected")
	}
	if _, err := ParseAttestedExpiry("not-a-date"); err == nil {
		t.Fatal("malformed expiry accepted")
	}
}
