package service_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/tl/event"
	"github.com/agentnameservice/ans/internal/tl/receipt"
	"github.com/agentnameservice/ans/internal/tl/service"
)

func TestCertificateOverlap_BadgeAndSignedStatusAgree(t *testing.T) {
	for _, tc := range []struct {
		name            string
		identityExpiry  time.Duration
		oldServerExpiry time.Duration
		newServerExpiry time.Duration
		status          service.BadgeStatus
		serverCount     int
	}{
		{"all-expired", -time.Hour, -2 * time.Hour, -time.Hour, service.BadgeExpired, 0},
		{"identity-expired", -time.Hour, -time.Hour, 90 * 24 * time.Hour, service.BadgeExpired, 0},
		{"expired-overlap", 90 * 24 * time.Hour, -time.Hour, 90 * 24 * time.Hour, service.BadgeActive, 1},
		{"valid-overlap", 90 * 24 * time.Hour, 5 * time.Minute, 90 * 24 * time.Hour, service.BadgeActive, 2},
		{"last-server-warning", 90 * 24 * time.Hour, -time.Hour, 24 * time.Hour, service.BadgeWarning, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := newReceiptTestbed(t)
			now := time.Now().UTC().Truncate(time.Second)
			tb.logSvc.WithClock(func() time.Time { return now })
			certInfo := func(id int, expiry time.Duration) event.CertificateInfo {
				return event.CertificateInfo{Fingerprint: fmt.Sprintf("SHA256:%064d", id),
					CertType: "X509-DV-SERVER", NotAfter: now.Add(expiry).Format(time.RFC3339)}
			}
			identity := certInfo(1, tc.identityExpiry)
			identity.CertType = "X509-OV-CLIENT"
			tb.inner.Attestations = &event.Attestations{
				IdentityCerts: []event.CertificateInfo{identity},
				ServerCerts:   []event.CertificateInfo{certInfo(2, tc.oldServerExpiry), certInfo(3, tc.newServerExpiry)},
			}
			id := tb.appendEvent(t)
			status, err := service.NewBadgeService(tb.logSvc).StatusOf(t.Context(), id)
			if err != nil || status != tc.status {
				t.Fatalf("badge = %q, want %q (error %v)", status, tc.status, err)
			}
			generator, err := receipt.NewKeyManagerStatusTokenGenerator(t.Context(), tb.tlKM, "tl-receipt", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			generator.WithClock(func() time.Time { return now })
			token, err := service.NewStatusTokenService(tb.logSvc, generator).ForAgent(t.Context(), id)
			if tc.status == service.BadgeExpired {
				if !errors.Is(err, service.ErrStatusTokenNotIssued) {
					t.Fatalf("expired agent got a token: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			payload, err := receipt.VerifyStatusToken(token.Bytes, tb.receiptPub)
			if err != nil {
				t.Fatal(err)
			}
			if payload.Status != string(tc.status) || len(payload.ValidServerCerts) != tc.serverCount ||
				len(payload.ValidIdentityCerts) != 1 {
				t.Fatalf("signed status/certificate set disagrees with current validity: %+v", payload)
			}
			if tc.oldServerExpiry > 0 && payload.EXP > now.Add(tc.oldServerExpiry).Unix() {
				t.Fatal("token outlives an included overlap certificate")
			}
			for _, fp := range payload.ValidServerCerts {
				if tc.oldServerExpiry <= 0 && fp.Fingerprint == certInfo(2, tc.oldServerExpiry).Fingerprint {
					t.Fatal("expired certificate retained in signed valid list")
				}
			}
		})
	}
}

func TestStatusToken_LegacyExpiryBoundsLifetime(t *testing.T) {
	tb := newReceiptTestbed(t)
	now := time.Now().UTC().Truncate(time.Second)
	tb.inner.ExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339)
	tb.appendEvent(t)
	tb.logSvc.WithClock(func() time.Time { return now })
	generator, err := receipt.NewKeyManagerStatusTokenGenerator(t.Context(), tb.tlKM, "tl-receipt", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	generator.WithClock(func() time.Time { return now })
	svc := service.NewStatusTokenService(tb.logSvc, generator)
	token, err := svc.ForAgent(t.Context(), tb.inner.AnsID)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifyStatusToken(token.Bytes, tb.receiptPub)
	if err != nil || payload.EXP != now.Add(5*time.Minute).Unix() {
		t.Fatalf("legacy expiry not applied: %+v, %v", payload, err)
	}
	tb.logSvc.WithClock(func() time.Time { return now.Add(5 * time.Minute) })
	if _, err := svc.ForAgent(t.Context(), tb.inner.AnsID); !errors.Is(err, service.ErrStatusTokenNotIssued) {
		t.Fatalf("expired legacy event got a token: %v", err)
	}
}
