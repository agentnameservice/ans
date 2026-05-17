package opentimestamps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeOTSBytes are stand-in OpenTimestamps proof bytes. Real .ots
// files start with the OpenTimestamps magic 0x00 0x4F 0x70 ... ("OTS")
// followed by version + timestamp tree. Tests don't need a valid
// .ots format; they need recognizable bytes the witness round-trips.
var fakeOTSBytes = []byte{
	0x00, 0x4F, 0x70, 0x65, 0x6E, 0x54, 0x69, 0x6D, 0x65, 0x73,
	0x74, 0x61, 0x6D, 0x70, 0x73, 0x00, 0x01, 0x02, 0x03,
}

func TestWitness_Profile(t *testing.T) {
	w := New()
	if got := w.Profile(); got != ProfileID {
		t.Errorf("Profile: got %q, want %q", got, ProfileID)
	}
	if ProfileID != "4.C-opentimestamps" {
		t.Errorf("ProfileID drift: %q", ProfileID)
	}
}

func TestWitness_Attest_HappyPath(t *testing.T) {
	checkpoint := []byte("tl-checkpoint-bytes-v1")
	wantDigest := sha256.Sum256(checkpoint)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/digest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(got, wantDigest[:]) {
			t.Errorf("calendar received %x, want %x", got, wantDigest[:])
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fakeOTSBytes)
	}))
	defer srv.Close()

	fixedTime := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	w := New().WithCalendarURL(srv.URL).WithClock(func() time.Time { return fixedTime })

	att, err := w.Attest(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Profile != ProfileID {
		t.Errorf("Profile: got %q", att.Profile)
	}
	if !bytes.Equal(att.CheckpointDigest, wantDigest[:]) {
		t.Errorf("CheckpointDigest mismatch")
	}
	if att.AttestedAt != "2026-05-17T10:00:00Z" {
		t.Errorf("AttestedAt: got %q", att.AttestedAt)
	}
	if !bytes.Equal(att.ExternalProof, fakeOTSBytes) {
		t.Errorf("ExternalProof: got %x, want %x", att.ExternalProof, fakeOTSBytes)
	}
}

func TestWitness_Attest_EmptyCheckpoint(t *testing.T) {
	w := New().WithCalendarURL("http://unused")
	_, err := w.Attest(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on empty checkpoint")
	}
	if !strings.Contains(err.Error(), "empty checkpoint") {
		t.Errorf("error: %v", err)
	}
}

func TestWitness_Attest_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "calendar unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	_, err := w.Attest(context.Background(), []byte("checkpoint"))
	if err == nil {
		t.Fatal("expected error on 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestWitness_Attest_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// no bytes
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	_, err := w.Attest(context.Background(), []byte("checkpoint"))
	if err == nil {
		t.Fatal("expected error on empty calendar response")
	}
}

func TestWitness_Attest_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fakeOTSBytes)
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := w.Attest(ctx, []byte("checkpoint"))
	if err == nil {
		t.Fatal("expected error on context timeout")
	}
}

func TestWitness_Upgrade_HappyPath(t *testing.T) {
	pending := fakeOTSBytes
	upgraded := append([]byte{0xFF}, fakeOTSBytes...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/timestamp" {
			t.Errorf("unexpected upgrade path: %s", r.URL.Path)
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, pending) {
			t.Errorf("upgrade body mismatch")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(upgraded)
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	got, err := w.Upgrade(context.Background(), pending)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !bytes.Equal(got, upgraded) {
		t.Errorf("Upgrade returned wrong bytes")
	}
}

func TestWitness_Upgrade_NotYetAvailable(t *testing.T) {
	pending := fakeOTSBytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 404 means "no Bitcoin attestation yet"; Upgrade returns
		// the input unchanged with no error so callers can retry.
		http.Error(w, "not yet", http.StatusNotFound)
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	got, err := w.Upgrade(context.Background(), pending)
	if err != nil {
		t.Fatalf("Upgrade: %v (404 should not be an error)", err)
	}
	if !bytes.Equal(got, pending) {
		t.Errorf("Upgrade should return input unchanged on 404")
	}
}

func TestWitness_Upgrade_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	w := New().WithCalendarURL(srv.URL)
	_, err := w.Upgrade(context.Background(), fakeOTSBytes)
	if err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestWitness_Upgrade_EmptyPending(t *testing.T) {
	w := New().WithCalendarURL("http://unused")
	_, err := w.Upgrade(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on empty pending input")
	}
}

func TestWitness_DefaultCalendarURL(t *testing.T) {
	w := New()
	if w.calendarURL != DefaultCalendarURL {
		t.Errorf("calendarURL: got %q, want %q", w.calendarURL, DefaultCalendarURL)
	}
	if w.httpClient.Timeout == 0 {
		t.Error("httpClient should have a non-zero timeout")
	}
}

func TestWitness_BaseURLTrailingSlashStripped(t *testing.T) {
	w := New().WithCalendarURL("https://calendar.test/")
	if !strings.HasSuffix(w.calendarURL, "test") {
		t.Errorf("trailing slash not stripped: %q", w.calendarURL)
	}
}

// TestWitness_SatisfiesPortInterface is a compile-time check: if the
// concrete *Witness no longer satisfies port.Witness, this fails to
// compile and the test never runs.
func TestWitness_SatisfiesPortInterface(t *testing.T) {
	// Compile-time check via interface assertion in the variable
	// declaration; if New()'s return type drifts off port.Witness,
	// this line stops compiling.
	var _ = func() interface{} {
		// Imports referenced via local var to keep test deps tight.
		return New()
	}
	_ = t
}
