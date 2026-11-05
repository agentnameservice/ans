package domain

import (
	"fmt"
	"time"
)

// ParseAttestedExpiry permits absent legacy expiry but rejects malformed evidence.
func ParseAttestedExpiry(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid attested certificate expiry: %w", err)
	}
	return parsed, nil
}
