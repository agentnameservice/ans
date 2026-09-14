package service_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/ra/service"
	"github.com/agentnameservice/ans/internal/tl/logstore"
	"github.com/agentnameservice/ans/internal/tl/producerkey"
	"github.com/agentnameservice/ans/internal/tl/receipt"
	tlservice "github.com/agentnameservice/ans/internal/tl/service"
)

// Drive real RA issuance and SQLite outbox snapshots into the real TL.
// Renewing one family must succeed while the other remains lapsed. A later
// renewal of the lapsed family restores current status without trusting its
// expired predecessor.
func TestCertificateRenewal_PreservesLapsedOtherFamily(t *testing.T) {
	for _, lane := range []string{"V1", "V2"} {
		for _, kind := range []string{"CSR", "BYOC"} {
			for _, lapsedFamily := range []string{"identity", "server"} {
				t.Run(lane+"/"+kind+"/lapsed-"+lapsedFamily, func(t *testing.T) {
					ctx := context.Background()
					fx := newRegFixture(t)
					id := registerAndActivate(t, fx, fx.svc)
					log, tokens, pub := newRenewalTestLog(t, fx)
					for _, initial := range fx.sealer.sealed() {
						appendRenewalTestEvent(t, log, initial.SchemaVersion,
							initial.InnerCanonical, initial.ProducerSig)
					}

					// Model stored certificate validity after time has passed,
					// without waiting for the fixture CA's certificate lifetime.
					expiredAt := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
					lapsedFingerprint := expireCertificateFamily(t, fx, id, lapsedFamily, expiredAt)
					renewedFamily := "server"
					if lapsedFamily == "server" {
						renewedFamily = "identity"
					}
					renewTestCertificate(t, fx, id, lane, renewedFamily, kind)
					snapshot := publishRenewalTestOutbox(t, fx, log)
					if snapshot.ExpiresAt != expiredAt.Format(time.RFC3339) {
						t.Fatalf("renewal extended a lapsed registration: expiresAt=%s, want %s",
							snapshot.ExpiresAt, expiredAt.Format(time.RFC3339))
					}
					certs := snapshot.certificates(lane, lapsedFamily)
					if len(certs) != 1 || certs[0].Fingerprint != lapsedFingerprint ||
						certs[0].NotAfter != expiredAt.Format(time.RFC3339) {
						t.Fatalf("lapsed certificate evidence was lost or changed: %+v", certs)
					}
					status, err := tlservice.NewBadgeService(log).StatusOf(ctx, id)
					if err != nil || status != tlservice.BadgeExpired {
						t.Fatalf("badge after partial renewal = %s, err=%v", status, err)
					}
					if _, err := tokens.ForAgent(ctx, id); !errors.Is(err, tlservice.ErrStatusTokenNotIssued) {
						t.Fatalf("partial renewal authorized an expired registration: %v", err)
					}

					renewTestCertificate(t, fx, id, lane, lapsedFamily, kind)
					publishRenewalTestOutbox(t, fx, log)
					status, err = tlservice.NewBadgeService(log).StatusOf(ctx, id)
					if err != nil || status != tlservice.BadgeActive {
						t.Fatalf("badge after both families renewed = %s, err=%v", status, err)
					}
					token, err := tokens.ForAgent(ctx, id)
					if err != nil {
						t.Fatal(err)
					}
					claims, err := receipt.VerifyStatusToken(token.Bytes, pub)
					if err != nil {
						t.Fatal(err)
					}
					if claims.Status != string(tlservice.BadgeActive) ||
						len(claims.ValidIdentityCerts) == 0 || len(claims.ValidServerCerts) == 0 {
						t.Fatalf("recovered token lacks required certificate families: %+v", claims)
					}
					for _, cert := range append(claims.ValidIdentityCerts, claims.ValidServerCerts...) {
						if cert.Fingerprint == lapsedFingerprint {
							t.Fatal("recovered token authorizes the expired predecessor")
						}
					}
				})
			}
		}
	}
}

func expireCertificateFamily(t *testing.T, fx *regFixture, id, family string, expiry time.Time) string {
	t.Helper()
	ctx := context.Background()
	if family == "identity" {
		sealed := fx.sealer.sealed()
		var initial renewalTestSnapshot
		if err := json.Unmarshal(sealed[len(sealed)-1].InnerCanonical, &initial); err != nil {
			t.Fatal(err)
		}
		if _, err := fx.db.DBX().ExecContext(ctx,
			"UPDATE issued_certificates SET expiration_timestamp_ms = ? WHERE agent_id = ?",
			expiry.UnixMilli(), id); err != nil {
			t.Fatal(err)
		}
		return initial.Attestations.IdentityCerts[0].Fingerprint
	}
	cert, err := fx.byoc.FindLatestValidByAgentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.DBX().ExecContext(ctx,
		"UPDATE byoc_certificates SET valid_to_ms = ? WHERE agent_id = ?",
		expiry.UnixMilli(), id); err != nil {
		t.Fatal(err)
	}
	return "SHA256:" + cert.Fingerprint
}

func renewTestCertificate(t *testing.T, fx *regFixture, id, lane, family, kind string) {
	t.Helper()
	ctx := context.Background()
	if family == "identity" {
		csr := testCSR(t, fx.req.AnsName.String())
		var err error
		if lane == "V1" {
			_, err = fx.svc.SubmitIdentityCSRV1(ctx, id, csr)
		} else {
			_, err = fx.svc.SubmitIdentityCSR(ctx, id, csr)
		}
		if err != nil {
			t.Fatalf("identity renewal must complete despite server lapse: %v", err)
		}
		return
	}
	if _, err := fx.svc.SubmitServerCertRenewal(ctx, id, renewalInput(t, fx, kind)); err != nil {
		t.Fatal(err)
	}
	var result *service.VerifyRenewalACMEResult
	var err error
	if lane == "V1" {
		result, err = fx.svc.VerifyRenewalACMEV1(ctx, id)
	} else {
		result, err = fx.svc.VerifyRenewalACME(ctx, id)
	}
	if err != nil {
		t.Fatalf("server renewal must complete despite identity lapse: %v", err)
	}
	if result.Renewal.CompletedAt.IsZero() {
		t.Fatal("server renewal did not complete")
	}
}

type renewalTestCertificate struct {
	Fingerprint string `json:"fingerprint"`
	NotAfter    string `json:"notAfter"`
}

type renewalTestSnapshot struct {
	EventType     string `json:"eventType"`
	RenewalStatus string `json:"renewalStatus"`
	ExpiresAt     string `json:"expiresAt"`
	Attestations  struct {
		IdentityCerts      []renewalTestCertificate `json:"identityCerts"`
		ServerCerts        []renewalTestCertificate `json:"serverCerts"`
		ValidIdentityCerts []renewalTestCertificate `json:"validIdentityCerts"`
		ValidServerCerts   []renewalTestCertificate `json:"validServerCerts"`
	} `json:"attestations"`
}

func (s renewalTestSnapshot) certificates(lane, family string) []renewalTestCertificate {
	if lane == "V1" {
		if family == "identity" {
			return s.Attestations.ValidIdentityCerts
		}
		return s.Attestations.ValidServerCerts
	}
	if family == "identity" {
		return s.Attestations.IdentityCerts
	}
	return s.Attestations.ServerCerts
}

func publishRenewalTestOutbox(t *testing.T, fx *regFixture, log *tlservice.LogService) renewalTestSnapshot {
	t.Helper()
	ctx := context.Background()
	rows, err := fx.outboxStore.Claim(ctx, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("renewal outbox rows=%d, err=%v", len(rows), err)
	}
	row := rows[0]
	var payload service.OutboxPayload
	if err := json.Unmarshal(row.PayloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	var snapshot renewalTestSnapshot
	if err := json.Unmarshal(payload.InnerEventCanonical, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.EventType != "AGENT_RENEWED" || snapshot.RenewalStatus != "SUCCESS" {
		t.Fatalf("renewal completion event = %+v", snapshot)
	}
	logID := appendRenewalTestEvent(t, log, row.SchemaVersion, payload.InnerEventCanonical, payload.ProducerSignature)
	if err := fx.outboxStore.MarkSent(ctx, row.ID, logID); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func appendRenewalTestEvent(t *testing.T, log *tlservice.LogService, lane string, body []byte, signature string) string {
	t.Helper()
	appendEvent := log.AppendV2
	if lane == "V1" {
		appendEvent = log.AppendV1
	}
	result, err := appendEvent(context.Background(), tlservice.AppendInput{
		RawBody: body, ProducerSignature: signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.LogID
}

func newRenewalTestLog(t *testing.T, fx *regFixture) (*tlservice.LogService, *tlservice.StatusTokenService, *ecdsa.PublicKey) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, err := logstore.NewC2SPECDSASigner(ctx, km, "tl-sign", "renewal-test")
	if err != nil {
		t.Fatal(err)
	}
	lg, err := logstore.Open(ctx, logstore.Config{
		DataDir: filepath.Join(dir, "tiles"), Origin: "renewal-test",
		BatchSize: 1, BatchMaxAge: time.Millisecond, CheckpointInterval: 100 * time.Millisecond,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := lg.Close(closeCtx); err != nil {
			t.Error(err)
		}
	})
	db, err := sqlitetl.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	keys, err := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{{
		RaID: fx.signer.RaID, KeyID: fx.signer.KeyID, Algorithm: "ES256", PublicKeyPEM: fx.signerPubPEM,
	}})
	if err != nil {
		t.Fatal(err)
	}
	log := tlservice.NewLogService(lg, sqlitetl.NewEventStore(db), sqlitetl.NewCheckpointStore(db),
		tlservice.NewProducerSigVerifier(keys), km, "tl-sign", "renewal-test")
	t.Cleanup(log.Close)
	generator, err := receipt.NewKeyManagerStatusTokenGenerator(ctx, km, "tl-sign", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := km.GetPublicKey(ctx, "tl-sign")
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected TL key type: %T", pub)
	}
	return log, tlservice.NewStatusTokenService(log, generator), ecdsaPub
}
