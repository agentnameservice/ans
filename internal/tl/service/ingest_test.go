package service_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/event"
	"github.com/agentnameservice/ans/internal/tl/logstore"
	"github.com/agentnameservice/ans/internal/tl/producerkey"
	"github.com/agentnameservice/ans/internal/tl/receipt"
	"github.com/agentnameservice/ans/internal/tl/service"
)

func appendFixture(t *testing.T, tb *receiptTestbed) *service.AppendResult {
	t.Helper()
	body, signature := tb.signedFixtureBody(t)
	result, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertTreeSize(t *testing.T, tb *receiptTestbed, expected uint64) {
	t.Helper()
	size, err := tb.log.Reader().IntegratedSize(t.Context())
	if err != nil || size != expected {
		t.Fatalf("integrated leaves = %d, want %d (error %v)", size, expected, err)
	}
}

func TestLogService_ConcurrentDuplicateSubmissionsAppendOnce(t *testing.T) {
	for _, lane := range []string{"V1", "V2"} {
		t.Run(lane, func(t *testing.T) {
			tb := newReceiptTestbed(t)
			body, signature := tb.signedFixtureBody(t)
			appendEvent := tb.logSvc.AppendV2
			if lane == "V1" {
				appendEvent = tb.logSvc.AppendV1
			}
			const requests = 16
			results := make([]*service.AppendResult, requests)
			errs := make([]error, requests)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range requests {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					results[i], errs[i] = appendEvent(t.Context(), service.AppendInput{
						RawBody: body, ProducerSignature: signature,
					})
				}()
			}
			close(start)
			wg.Wait()
			created := 0
			for i, r := range results {
				if errs[i] != nil {
					t.Fatalf("request %d: %v", i, errs[i])
				}
				if !r.Duplicate {
					created++
				}
				if r.LeafIndex != 0 || r.LogID != results[0].LogID ||
					!bytes.Equal(r.LeafHash[:], results[0].LeafHash[:]) {
					t.Fatal("duplicate did not return the original leaf and log ID")
				}
			}
			if created != 1 {
				t.Fatalf("fresh appends = %d, want 1", created)
			}
			assertTreeSize(t, tb, 1)
		})
	}
}

func TestLogService_RejectsConflictingStatesAllowsChangedRenewals(t *testing.T) {
	tb := newReceiptTestbed(t)
	first := appendFixture(t, tb)
	tb.inner.Timestamp = "2026-04-18T00:00:00Z"
	tb.inner.IssuedAt = tb.inner.Timestamp
	retry := appendFixture(t, tb)
	if !retry.Duplicate || retry.LogID != first.LogID {
		t.Fatal("timestamp-only state retry appended another leaf")
	}
	base := tb.inner
	baseAgent := *tb.inner.Agent
	for _, scenario := range []struct {
		name string
		edit func()
	}{
		{"repeat-registration-with-new-data", func() { tb.inner.Agent.Name = "changed" }},
		{"different-agent-same-name", func() { tb.inner.AnsID = "10000000-0000-4000-8000-000000000099" }},
		{"same-agent-different-name", func() {
			tb.inner.AnsName = "ans://v2.0.0.rcpt.example.com"
			tb.inner.Agent.Version = "2.0.0"
		}},
		{"version-mismatch", func() { tb.inner.Agent.Version = "9.0.0" }},
		{"host-mismatch", func() { tb.inner.Agent.Host = "other.example.com" }},
		{"noncanonical-name", func() {
			tb.inner.AnsName = "ans://v1.0.0.RCPT.example.com"
			tb.inner.AnsID = "10000000-0000-4000-8000-000000000099"
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			tb.inner = base
			agent := baseAgent
			tb.inner.Agent = &agent
			scenario.edit()
			body, signature := tb.signedFixtureBody(t)
			_, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature})
			want := "AGENT_STATE_CONFLICT"
			switch scenario.name {
			case "version-mismatch", "host-mismatch", "noncanonical-name":
				want = "INVALID_EVENT"
			}
			var de *domain.Error
			if !errors.As(err, &de) || de.Code != want {
				t.Fatalf("%s: got %v, want %s", scenario.name, err, want)
			}
			assertTreeSize(t, tb, 1)
		})
	}
	tb.inner = base
	tb.inner.Agent = &baseAgent
	tb.inner.EventType = event.TypeAgentRenewed
	for i := range 2 {
		tb.inner.Attestations = &event.Attestations{ServerCerts: []event.CertificateInfo{{
			Fingerprint: fmt.Sprintf("SHA256:%064d", i),
			CertType:    "X509-DV-SERVER", NotAfter: "2030-01-01T00:00:00Z",
		}}}
		result := appendFixture(t, tb)
		if result.Duplicate || result.LeafIndex != uint64(i+1) {
			t.Fatal("a changed renewal was suppressed")
		}
	}
	tb.inner.EventType = event.TypeAgentRevoked
	tb.inner.Timestamp = "2026-04-19T00:00:00Z"
	appendFixture(t, tb)
	tb.inner.EventType = event.TypeAgentRenewed
	tb.inner.Timestamp = "2026-04-20T00:00:00Z"
	body, signature := tb.signedFixtureBody(t)
	if _, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature}); err == nil {
		t.Fatal("revoked agent resurrected")
	}
	assertTreeSize(t, tb, 4)
}

func TestLogService_RecoversAppendWhoseIndexWriteFailed(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%t", restart), func(t *testing.T) {
			tb := newReceiptTestbed(t)
			_, err := tb.db.DBX().Exec(`CREATE TRIGGER fail_event_insert BEFORE INSERT ON tl_events
				BEGIN SELECT RAISE(FAIL, 'injected index failure'); END`)
			if err != nil {
				t.Fatal(err)
			}
			body, signature := tb.signedFixtureBody(t)
			if _, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature}); err == nil {
				t.Fatal("index failure swallowed")
			}
			assertTreeSize(t, tb, 1)
			if _, err := tb.db.DBX().Exec("DROP TRIGGER fail_event_insert"); err != nil {
				t.Fatal(err)
			}
			if restart {
				tb.logSvc.Close()
				cfg := logstore.Config{DataDir: tb.log.DataDir(), Origin: "ans-test",
					BatchSize: 1, BatchMaxAge: time.Millisecond, CheckpointInterval: 100 * time.Millisecond}
				signer := tb.log.Signer()
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				if err := tb.log.Close(ctx); err != nil {
					t.Fatal(err)
				}
				lg, err := logstore.Open(t.Context(), cfg, signer)
				if err != nil {
					t.Fatal(err)
				}
				tb.log = lg
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					if err := lg.Close(ctx); err != nil {
						t.Error(err)
					}
				})
				restartIndexService(t, tb)
			}
			retry := appendFixture(t, tb)
			if !retry.Duplicate || retry.LeafIndex != 0 {
				t.Fatal("retry after index failure added a second leaf")
			}
			original, err := sqlitetl.NewEventStore(tb.db).GetEventByLeafIndex(t.Context(), 0)
			if err != nil || retry.LogID != original.LogID {
				t.Fatalf("recovery lost original log ID: %v", err)
			}
			retryAgain := appendFixture(t, tb)
			if retryAgain.LogID != original.LogID || !retryAgain.Duplicate {
				t.Fatal("recovered event is not idempotent")
			}
			assertTreeSize(t, tb, 1)
		})
	}
}

func restartIndexService(t *testing.T, tb *receiptTestbed) {
	t.Helper()
	tb.logSvc.Close()
	tb.logSvc = service.NewLogService(tb.log, sqlitetl.NewEventStore(tb.db),
		sqlitetl.NewCheckpointStore(tb.db), tb.producerSig, tb.tlKM, "tl-attest", "ans-test")
	t.Cleanup(tb.logSvc.Close)
}

// Older ingestion could append two envelopes for the same producer event,
// then fail the second index insert. Recovery must represent both committed
// leaves without appending again or changing either envelope's signed bytes.
func TestLogService_RecoversHistoricalDuplicateLeaves(t *testing.T) {
	tb := newReceiptTestbed(t)
	first := appendFixture(t, tb)
	store := sqlitetl.NewEventStore(tb.db)
	original, err := store.GetEventByLeafIndex(t.Context(), first.LeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	env, err := original.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	env.Payload.LogID = "02000000-0000-7000-8000-000000000002"
	env.Signature = ""
	input, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	env.Signature, err = anscrypto.SignDetachedJWS(t.Context(), tb.tlKM, "tl-attest",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: time.Now().Unix(), RAID: "ans-test"}, input)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := tb.log.Append(t.Context(), env)
	if err != nil {
		t.Fatal(err)
	}
	assertTreeSize(t, tb, 2)
	if err := tb.logSvc.RecoverIndex(t.Context()); err != nil {
		t.Fatalf("recover a previously committed duplicate: %v", err)
	}
	recovered, err := store.GetEventByLeafIndex(t.Context(), duplicate.LeafIndex)
	if err != nil || recovered.RawEvent != string(duplicate.Canonical) {
		t.Fatalf("historical leaf bytes were not preserved: %v", err)
	}
	if recovered.EventHashHex != original.EventHashHex || recovered.LogID == original.LogID {
		t.Fatal("fixture did not preserve distinct envelopes of the same event")
	}
	restartIndexService(t, tb)
	retry := appendFixture(t, tb)
	if !retry.Duplicate || retry.LeafIndex != first.LeafIndex || retry.LogID != first.LogID {
		t.Fatal("retry did not return the original committed leaf")
	}
	assertTreeSize(t, tb, 2)
	next, err := store.FirstUnindexedLeaf(t.Context())
	if err != nil || next != 2 {
		t.Fatalf("recovered index still has a gap: next=%d err=%v", next, err)
	}
}

func TestLogService_RepairsIndexGapBeforeLaterRows(t *testing.T) {
	tb := newReceiptTestbed(t)
	first := appendFixture(t, tb)
	tb.inner.AnsID = "10000000-0000-4000-8000-000000000099"
	tb.inner.AnsName = "ans://v1.0.0.other.example.com"
	tb.inner.Agent.Host = "other.example.com"
	second := appendFixture(t, tb)
	if _, err := tb.db.DBX().Exec("DELETE FROM tl_events WHERE leaf_index = 0"); err != nil {
		t.Fatal(err)
	}
	restartIndexService(t, tb)
	if err := tb.logSvc.RecoverIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Read recovery runs before the HTTP listener starts; no new append is
	// needed to make an already committed leaf visible.
	if rec, err := tb.logSvc.EventByLeafIndex(t.Context(), 0); err != nil || rec.LogID != first.LogID {
		t.Fatalf("startup recovery left an already committed leaf invisible: %v", err)
	}
	retry := appendFixture(t, tb)
	if !retry.Duplicate || retry.LogID != second.LogID {
		t.Fatal("later row changed during recovery")
	}
	restored, err := sqlitetl.NewEventStore(tb.db).GetEventByLeafIndex(t.Context(), 0)
	if err != nil || restored.LogID != first.LogID {
		t.Fatalf("missing earlier row was not restored: %v", err)
	}
	assertTreeSize(t, tb, 2)
}

func TestLogService_IndexAheadOfLogFailsClosed(t *testing.T) {
	tb := newReceiptTestbed(t)
	appendFixture(t, tb)
	if _, err := tb.db.DBX().Exec("UPDATE tl_events SET leaf_index = 99"); err != nil {
		t.Fatal(err)
	}
	restartIndexService(t, tb)
	if err := tb.logSvc.RecoverIndex(t.Context()); err == nil {
		t.Fatal("index from a larger log accepted")
	}
	body, signature := tb.signedFixtureBody(t)
	if _, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature}); err == nil {
		t.Fatal("append accepted while index recovery was incomplete")
	}
	assertTreeSize(t, tb, 1)
}

func TestLogService_FailedRevocationIndexCannotMintStaleActiveToken(t *testing.T) {
	tb := newReceiptTestbed(t)
	appendFixture(t, tb)
	if _, err := tb.db.DBX().Exec(`CREATE TRIGGER fail_event_insert BEFORE INSERT ON tl_events
		BEGIN SELECT RAISE(FAIL, 'injected index failure'); END`); err != nil {
		t.Fatal(err)
	}
	tb.inner.EventType = event.TypeAgentRevoked
	body, signature := tb.signedFixtureBody(t)
	if _, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: signature}); err == nil {
		t.Fatal("index failure swallowed")
	}
	generator, err := receipt.NewKeyManagerStatusTokenGenerator(t.Context(), tb.tlKM, "tl-receipt", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status := service.NewStatusTokenService(tb.logSvc, generator)
	if _, err := status.ForAgent(t.Context(), tb.inner.AnsID); err == nil {
		t.Fatal("committed revocation with a failed index write still minted ACTIVE")
	}
	if _, err := tb.db.DBX().Exec("DROP TRIGGER fail_event_insert"); err != nil {
		t.Fatal(err)
	}
	if _, err := status.ForAgent(t.Context(), tb.inner.AnsID); !errors.Is(err, service.ErrStatusTokenNotIssued) {
		t.Fatalf("read did not recover the revocation before serving status: %v", err)
	}
	assertTreeSize(t, tb, 2)
}

func TestLogService_RejectsOlderNonterminalSnapshotWithSpecificCode(t *testing.T) {
	tb := newReceiptTestbed(t)
	appendFixture(t, tb)
	tb.inner.EventType = event.TypeAgentRenewed
	tb.inner.Timestamp = "2000-01-01T00:00:00Z"
	tb.inner.Agent.Name = "older renewal"
	body, sig := tb.signedFixtureBody(t)
	_, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: sig})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "STALE_AGENT_EVENT" {
		t.Fatalf("wanted stale-event code: %v", err)
	}
	assertTreeSize(t, tb, 1)
}

func TestLogService_DeprecationCannotBeReversedByRenewal(t *testing.T) {
	tb := newReceiptTestbed(t)
	appendFixture(t, tb)
	tb.inner.EventType = event.TypeAgentDeprecated
	tb.inner.Timestamp = "2030-01-01T00:00:00Z"
	appendFixture(t, tb)
	tb.inner.EventType = event.TypeAgentRenewed
	tb.inner.Timestamp = "2030-01-02T00:00:00Z"
	body, sig := tb.signedFixtureBody(t)
	_, err := tb.logSvc.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: sig})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "AGENT_STATE_CONFLICT" {
		t.Fatalf("wanted lifecycle conflict: %v", err)
	}
	assertTreeSize(t, tb, 2)
	tb.inner.EventType = event.TypeAgentRevoked
	appendFixture(t, tb)
	assertTreeSize(t, tb, 3)
}

func TestLogService_RejectsTrustedForeignProducerWithSpecificCode(t *testing.T) {
	tb := newReceiptTestbed(t)
	appendFixture(t, tb)
	km, pub := newTestKM(t, "foreign-key")
	keys, err := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{{RaID: "foreign-ra", KeyID: "foreign-key", Algorithm: "ES256", PublicKeyPEM: pub}})
	if err != nil {
		t.Fatal(err)
	}
	log := service.NewLogService(tb.log, sqlitetl.NewEventStore(tb.db), sqlitetl.NewCheckpointStore(tb.db), service.NewProducerSigVerifier(keys), tb.tlKM, "tl-attest", "ans-test")
	t.Cleanup(log.Close)
	tb.inner.RaID = "foreign-ra"
	tb.inner.EventType = event.TypeAgentRenewed
	tb.raID = "foreign-ra"
	tb.producerID = "foreign-key"
	tb.producerKM = km
	body, sig := tb.signedFixtureBody(t)
	_, err = log.AppendV2(t.Context(), service.AppendInput{RawBody: body, ProducerSignature: sig})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "AGENT_STATE_CONFLICT" {
		t.Fatalf("foreign producer was not rejected by state binding: %v", err)
	}
	assertTreeSize(t, tb, 1)
}
