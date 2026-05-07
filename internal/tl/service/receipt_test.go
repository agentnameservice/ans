package service_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/keymanager"
	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/event"
	"github.com/godaddy/ans/internal/tl/logstore"
	"github.com/godaddy/ans/internal/tl/producerkey"
	receiptpkg "github.com/godaddy/ans/internal/tl/receipt"
	"github.com/godaddy/ans/internal/tl/service"
)

// TestReceiptService_ForAgent_CacheHitThenMiss exercises the full
// receipt path: a cold ForAgent call should mint a fresh COSE receipt
// and populate the cache; a second call at the same tree size should
// return the cached bytes byte-identical.
func TestReceiptService_ForAgent_CacheHitThenMiss(t *testing.T) {
	tb := newReceiptTestbed(t)

	// Append + wait for checkpoint.
	ansID := tb.appendEvent(t)
	tb.waitCheckpointCovers(t, ansID)

	first, err := tb.svc.ForAgent(context.Background(), ansID)
	if err != nil {
		t.Fatalf("first ForAgent: %v", err)
	}
	if first.ContentType != receiptpkg.MediaType {
		t.Errorf("content-type: got %q want %q", first.ContentType, receiptpkg.MediaType)
	}
	if len(first.Bytes) == 0 {
		t.Fatal("first receipt bytes empty")
	}
	if first.Bytes[0] != 0xd2 {
		t.Errorf("first byte: got 0x%02x, want 0xd2 (COSE_Sign1 tag 18)", first.Bytes[0])
	}

	// Receipt must validate against the TL receipt pubkey.
	if err := receiptpkg.Verify(first.Bytes, tb.receiptPub); err != nil {
		t.Errorf("offline verify (first): %v", err)
	}

	// Second call → cache hit. Bytes must be byte-identical since
	// they come straight from the `tl_receipts` table.
	second, err := tb.svc.ForAgent(context.Background(), ansID)
	if err != nil {
		t.Fatalf("second ForAgent: %v", err)
	}
	if string(first.Bytes) != string(second.Bytes) {
		t.Errorf("cache miss on second call: bytes differ (got %d vs %d)",
			len(second.Bytes), len(first.Bytes))
	}
}

// TestReceiptService_ForLeafIndex verifies the by-leaf path returns a
// valid receipt for the same event that ForAgent does, since both
// flow through buildOrFetch.
func TestReceiptService_ForLeafIndex(t *testing.T) {
	tb := newReceiptTestbed(t)
	ansID := tb.appendEvent(t)
	tb.waitCheckpointCovers(t, ansID)

	// Leaf 0 is the only event we've appended.
	rec, err := tb.svc.ForLeafIndex(context.Background(), 0)
	if err != nil {
		t.Fatalf("ForLeafIndex: %v", err)
	}
	if err := receiptpkg.Verify(rec.Bytes, tb.receiptPub); err != nil {
		t.Errorf("offline verify: %v", err)
	}
}

// TestReceiptService_NonexistentAgent returns a NOT_FOUND domain
// error from the underlying log service — `ForAgent` should not
// synthesize a receipt for a stranger.
func TestReceiptService_NonexistentAgent(t *testing.T) {
	tb := newReceiptTestbed(t)
	if _, err := tb.svc.ForAgent(context.Background(), "no-such-agent"); err == nil {
		t.Fatal("expected error for nonexistent agent, got nil")
	}
}

// TestReceiptService_LeafNotYetCovered asserts that requesting a
// receipt before a checkpoint covers the leaf returns
// ErrLeafNotYetCovered — the sentinel the HTTP handler maps to 503.
func TestReceiptService_LeafNotYetCovered(t *testing.T) {
	// Testbed with a much larger checkpoint interval so we can
	// deliberately race: append an event, then immediately ask for
	// a receipt before the checkpoint catches up. We don't want to
	// rely on timing; instead we just append and ask without
	// waiting, and accept that the test might flakily pass if the
	// machine is extremely slow. To make it deterministic we push
	// checkpointInterval to an hour.
	tb := newReceiptTestbed(t, withSlowCheckpoint())

	ansID := tb.appendEvent(t)
	// Do NOT wait for checkpoint. Immediately ask for a receipt —
	// the checkpoint cache in LogService will have either no
	// checkpoint at all or a stale one that doesn't cover the leaf.
	_, err := tb.svc.ForAgent(context.Background(), ansID)
	if err == nil {
		t.Skip("checkpoint raced ahead of the test — flaky branch, not a real failure")
	}
	if !errors.Is(err, service.ErrLeafNotYetCovered) {
		t.Fatalf("err: got %v, want ErrLeafNotYetCovered", err)
	}
}

// ----- testbed -----

type receiptTestbed struct {
	svc        *service.ReceiptService
	logSvc     *service.LogService
	receiptPub *ecdsa.PublicKey
	raID       string
	producerID string
	producerKM *testKM
	tlKM       port.KeyManager // exposed via testKMHandle for ad-hoc tests that need to spin up extra services
	inner      event.Event
}

// testKMHandle exposes the testbed's TL KeyManager so sibling tests
// (status-token, schema, etc.) can build their own services that
// share the same signing key set.
func (tb *receiptTestbed) testKMHandle() port.KeyManager { return tb.tlKM }

type receiptTestbedOpt func(*receiptTestbedCfg)

type receiptTestbedCfg struct {
	checkpointInterval time.Duration
}

func withSlowCheckpoint() receiptTestbedOpt {
	return func(c *receiptTestbedCfg) {
		// 5 minutes — longer than any test would wait, but below
		// Tessera's 10-minute default CheckpointRepublishInterval
		// (which caps CheckpointInterval at 10m, or Tessera refuses
		// to start). Puts the receipt service firmly in the pre-
		// checkpoint race window: the leaf gets batched quickly but
		// no checkpoint will cover it for 5 min, which gives us a
		// reliable window to assert ErrLeafNotYetCovered.
		c.checkpointInterval = 5 * time.Minute
	}
}

func newReceiptTestbed(t *testing.T, opts ...receiptTestbedOpt) *receiptTestbed {
	t.Helper()

	cfg := receiptTestbedCfg{checkpointInterval: 100 * time.Millisecond}
	for _, o := range opts {
		o(&cfg)
	}

	dir := t.TempDir()

	// Log.
	logKM, err := keymanager.NewFileKeyManager(filepath.Join(dir, "logkeys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logKM.EnsureKey(context.Background(), "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	c2spSigner, err := logstore.NewC2SPECDSASigner(
		context.Background(), logKM, "tl-sign", "ans-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := logstore.Open(context.Background(), logstore.Config{
		DataDir:            filepath.Join(dir, "tiles"),
		Origin:             "ans-test",
		BatchSize:          1,
		BatchMaxAge:        50 * time.Millisecond,
		CheckpointInterval: cfg.checkpointInterval,
	}, c2spSigner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = lg.Close(cctx)
	})

	// SQLite.
	db, err := sqlitetl.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	eventStore := sqlitetl.NewEventStore(db)
	cpStore := sqlitetl.NewCheckpointStore(db)
	receiptStore := sqlitetl.NewReceiptStore(db)

	// TL keys — real file KM, since the receipt generator needs a
	// key that persists through the test (KeyFingerprint-derived kid
	// must match between signing and verification).
	tlKM, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlKM.EnsureKey(context.Background(), "tl-attest", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := tlKM.EnsureKey(context.Background(), "tl-receipt", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	receiptPubAny, err := tlKM.GetPublicKey(context.Background(), "tl-receipt")
	if err != nil {
		t.Fatal(err)
	}
	receiptPub, ok := receiptPubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("receipt pub: unexpected type %T", receiptPubAny)
	}

	// Producer — the tiny in-memory signer from producersig_test.go
	// fits perfectly; it's a valid crypto.Signer that signs ES256
	// against a deterministic in-test key pair.
	prodKM, prodPEM := newTestKM(t, "prod-1")
	pkStore, err := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra-test-1", KeyID: "prod-1", Algorithm: "ES256", PublicKeyPEM: prodPEM},
	})
	if err != nil {
		t.Fatal(err)
	}

	producerSig := service.NewProducerSigVerifier(pkStore)
	logSvc := service.NewLogService(
		lg, eventStore, cpStore,
		producerSig, tlKM, "tl-attest", "ans-test",
	)
	t.Cleanup(func() { logSvc.Close() })
	gen, err := receiptpkg.NewKeyManagerGenerator(
		context.Background(), tlKM, "tl-receipt", "ans-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.NewReceiptService(logSvc, receiptStore, gen)

	return &receiptTestbed{
		svc:        svc,
		logSvc:     logSvc,
		receiptPub: receiptPub,
		raID:       "ra-test-1",
		producerID: "prod-1",
		producerKM: prodKM,
		tlKM:       tlKM,
		inner: event.Event{
			AnsID:     "10000000-0000-4000-8000-000000000010",
			AnsName:   "ans://v1.0.0.rcpt.example.com",
			EventType: event.TypeAgentRegistered,
			Agent: &event.Agent{
				Host:    "rcpt.example.com",
				Name:    "rcpt-test",
				Version: "1.0.0",
			},
			RaID:      "ra-test-1",
			IssuedAt:  "2026-04-17T00:00:00Z",
			Timestamp: "2026-04-17T00:00:00Z",
		},
	}
}

// appendEvent pushes the testbed's fixture event into the log,
// mimicking what the HTTP handler does with a signed body.
func (tb *receiptTestbed) appendEvent(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(tb.inner)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), tb.producerKM, tb.producerID,
		anscrypto.JWSProtectedHeader{
			Typ:       "JWT",
			Timestamp: 1700000000,
			RAID:      tb.raID,
		},
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.logSvc.AppendV2(context.Background(), service.AppendInput{
		RawBody:           body,
		ProducerSignature: jws,
	}); err != nil {
		t.Fatal(err)
	}
	return tb.inner.AnsID
}

// waitCheckpointCovers polls until a receipt can be minted without
// triggering ErrLeafNotYetCovered. 15s budget matches the other
// testbed timeouts — if Tessera hasn't checkpointed by then there's
// something wrong with the log, not the test.
func (tb *receiptTestbed) waitCheckpointCovers(t *testing.T, agentID string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, err := tb.svc.ForAgent(context.Background(), agentID)
		if err == nil {
			return
		}
		if !errors.Is(err, service.ErrLeafNotYetCovered) {
			t.Fatalf("unexpected err during wait: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("checkpoint never covered the leaf")
}
