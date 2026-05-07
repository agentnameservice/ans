package logstore_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/event"
	"github.com/godaddy/ans/internal/tl/logstore"
)

// TestLog_AppendAndCheckpoint exercises the full Tessera integration:
// open a log, append one event, wait for a checkpoint to be signed,
// and verify the checkpoint file on disk carries the expected origin
// and a C2SP ECDSA signature.
func TestLog_AppendAndCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	origin := "ans-test-log"

	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	require.NoError(t, err)
	_, err = km.EnsureKey(ctx, "tl-sign", port.AlgorithmECDSAP256)
	require.NoError(t, err)

	signer, err := logstore.NewC2SPECDSASigner(ctx, km, "tl-sign", origin)
	require.NoError(t, err)

	lg, err := logstore.Open(ctx, logstore.Config{
		DataDir:            filepath.Join(dir, "tiles"),
		Origin:             origin,
		BatchSize:          1,
		BatchMaxAge:        100 * time.Millisecond,
		CheckpointInterval: 200 * time.Millisecond,
	}, signer)
	require.NoError(t, err)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		_ = lg.Close(cctx)
	})

	// Pre-signed envelope — in real code the TL signs before calling
	// Append, but for the smoke test we just stamp any non-empty
	// signature so LeafBytes succeeds.
	env := event.BuildEnvelope(
		"tc-0001",
		&event.Event{
			AnsID:     "agent-xyz",
			AnsName:   "ans://v1.0.0.agent.example.com",
			EventType: event.TypeAgentRegistered,
			Agent: &event.Agent{
				Host:    "agent.example.com",
				Name:    "test",
				Version: "1.0.0",
			},
			RaID:      "ra-local",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		},
		"k1",
		"producer-sig-placeholder",
	)
	env.Signature = "tl-attest-placeholder"

	res, err := lg.Append(ctx, env)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), res.LeafIndex)
	assert.False(t, res.IsDuplicate)

	// Tessera antispam is off by default; we deduplicate at the
	// event-store layer before calling Append. Verify the raw second
	// append is treated as a fresh leaf with the next index.
	res2, err := lg.Append(ctx, env)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), res2.LeafIndex,
		"without antispam Tessera assigns a new index for each Add")

	// Wait for Tessera to sign and write a checkpoint.
	cpPath := filepath.Join(dir, "tiles", "checkpoint")
	deadline := time.Now().Add(5 * time.Second)
	var cpBytes []byte
	for time.Now().Before(deadline) {
		cpBytes, err = os.ReadFile(cpPath)
		if err == nil && len(cpBytes) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NotEmpty(t, cpBytes, "checkpoint file should be written")

	// The checkpoint note first line is the origin.
	firstLine := strings.SplitN(string(cpBytes), "\n", 2)[0]
	assert.Equal(t, origin, firstLine)

	// A signature line must follow the blank-line separator. Format
	// per sumdb-note: `— <origin> <base64>`. We look for the em-dash
	// to confirm Tessera actually ran our signer.
	assert.Contains(t, string(cpBytes), "— "+origin+" ",
		"checkpoint should carry at least one `— <origin> <b64>` line")
}
