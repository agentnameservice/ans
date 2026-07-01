package handler

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestPageTokenRoundTrip(t *testing.T) {
	t.Parallel()
	h := queryHash("flights", map[string][]string{"tags": {"travel"}})
	tok := pageToken{Offset: 42, QueryHash: h}
	encoded := encodePageToken(tok)
	got, err := decodePageToken(encoded, h)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Offset != 42 || got.QueryHash != h {
		t.Errorf("round trip: %+v", got)
	}
}

func TestDecodePageToken_Errors(t *testing.T) {
	t.Parallel()
	valid := encodePageToken(pageToken{Offset: 1, QueryHash: 7})

	t.Run("bad base64", func(t *testing.T) {
		if _, err := decodePageToken("!!!", 7); err == nil {
			t.Error("expected base64 error")
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
		if _, err := decodePageToken(short, 7); err == nil {
			t.Error("expected length error")
		}
	})
	t.Run("hash mismatch", func(t *testing.T) {
		if _, err := decodePageToken(valid, 999); err == nil {
			t.Error("expected hash-mismatch error")
		}
	})
	t.Run("negative offset", func(t *testing.T) {
		buf := make([]byte, 16)
		// Max uint64 → negative when cast to int.
		binary.BigEndian.PutUint64(buf[0:8], ^uint64(0))
		binary.BigEndian.PutUint64(buf[8:16], 7)
		neg := base64.RawURLEncoding.EncodeToString(buf)
		if _, err := decodePageToken(neg, 7); err == nil {
			t.Error("expected negative-offset error")
		}
	})
}

func TestQueryHash_StableAcrossFilterKeyOrder(t *testing.T) {
	t.Parallel()
	// Same logical filter, different map construction order → same hash.
	a := queryHash("x", map[string][]string{"tags": {"t"}, "type": {"y"}})
	b := queryHash("x", map[string][]string{"type": {"y"}, "tags": {"t"}})
	if a != b {
		t.Errorf("filter hash not order-stable: %d vs %d", a, b)
	}
	// Different text → different hash.
	if queryHash("x", nil) == queryHash("z", nil) {
		t.Error("text should affect the hash")
	}
	// Different filter value → different hash.
	if queryHash("x", map[string][]string{"tags": {"t"}}) ==
		queryHash("x", map[string][]string{"tags": {"u"}}) {
		t.Error("filter value should affect the hash")
	}
}
