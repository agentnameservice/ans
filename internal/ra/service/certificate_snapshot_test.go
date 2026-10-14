package service

import (
	"slices"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

func TestCertificateSnapshots_RetainLapseEvidenceWithoutAuthorizingInvalidCerts(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset []time.Duration
		want   []int
	}{
		{"absent-optional-family", nil, nil},
		{"both-valid", []time.Duration{time.Hour, 2 * time.Hour}, []int{0, 1}},
		{"expired-overlap", []time.Duration{-time.Hour, time.Hour}, []int{1}},
		{"all-lapsed", []time.Duration{-2 * time.Hour, -time.Hour}, []int{1}},
		{"latest-expiry-not-latest-issue", []time.Duration{-time.Hour, -2 * time.Hour}, []int{0}},
		{"expiry-boundary", []time.Duration{-time.Hour, 0}, []int{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identities := make([]*domain.StoredCertificate, 0, len(tc.offset)+4)
			servers := make([]*domain.ByocServerCertificate, 0, len(tc.offset)+4)
			for i, offset := range tc.offset {
				id := string(rune('a' + i))
				identities = append(identities, &domain.StoredCertificate{
					CSRID: id, Status: domain.CertStatusValid,
					IssueTimestamp: now.Add(-24 * time.Hour), ExpirationTimestamp: now.Add(offset),
				})
				servers = append(servers, &domain.ByocServerCertificate{
					Fingerprint: id, ValidFromTimestamp: now.Add(-24 * time.Hour), ValidToTimestamp: now.Add(offset),
				})
			}
			// Neither future-dated credentials nor incomplete entries can
			// make a lapsed family appear usable. Revocation is also excluded.
			identities = append(identities, nil,
				&domain.StoredCertificate{Status: domain.CertStatusValid},
				&domain.StoredCertificate{Status: domain.CertStatusValid,
					IssueTimestamp: now.Add(time.Hour), ExpirationTimestamp: now.Add(24 * time.Hour)},
				&domain.StoredCertificate{Status: domain.CertStatusRevoked, ExpirationTimestamp: now.Add(24 * time.Hour)})
			servers = append(servers, nil, &domain.ByocServerCertificate{},
				&domain.ByocServerCertificate{ValidFromTimestamp: now.Add(time.Hour), ValidToTimestamp: now.Add(24 * time.Hour)})
			if len(tc.offset) > 0 {
				servers = append(servers, servers[0])
			}
			identitySnapshot := attestedIdentityCerts(identities, now)
			serverSnapshot := serverCertsForAttestation(servers, now)
			gotIdentity := make([]string, 0, len(identitySnapshot))
			gotServer := make([]string, 0, len(serverSnapshot))
			want := make([]string, 0, len(tc.want))
			for _, i := range tc.want {
				want = append(want, string(rune('a'+i)))
			}
			for _, c := range identitySnapshot {
				gotIdentity = append(gotIdentity, c.CSRID)
			}
			for _, c := range serverSnapshot {
				gotServer = append(gotServer, c.Fingerprint)
			}
			if !slices.Equal(gotIdentity, want) || !slices.Equal(gotServer, want) {
				t.Fatalf("identity=%v server=%v, want %v", gotIdentity, gotServer, want)
			}
		})
	}
}

func TestAgentCertExpiry_LapsedFamilyStillBoundsRenewal(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		identity time.Duration
		server   time.Duration
	}{
		{"identity-lapsed", -time.Hour, 90 * 24 * time.Hour},
		{"server-lapsed", 90 * 24 * time.Hour, -time.Hour},
		{"both-lapsed", -time.Hour, -2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identities := []*domain.StoredCertificate{
				{Status: domain.CertStatusValid, ExpirationTimestamp: now.Add(tc.identity)},
				{Status: domain.CertStatusValid, IssueTimestamp: now.Add(time.Hour), ExpirationTimestamp: now.AddDate(1, 0, 0)},
			}
			servers := []*domain.ByocServerCertificate{
				{ValidToTimestamp: now.Add(tc.server)},
				{ValidFromTimestamp: now.Add(time.Hour), ValidToTimestamp: now.AddDate(1, 0, 0)},
			}
			want := now.Add(min(tc.identity, tc.server)).Format(time.RFC3339)
			if got := agentCertExpiry(identities, servers, now); got != want {
				t.Fatalf("expiresAt=%s, want %s", got, want)
			}
		})
	}
}
