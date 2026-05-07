package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ----- WithStaticSubject -----

func TestWithStaticSubject_OverridesDefault(t *testing.T) {
	p := NewStaticProvider("k", WithStaticSubject("ops-bot"))
	if p.subject != "ops-bot" {
		t.Errorf("subject: got %q, want ops-bot", p.subject)
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer k")
	id, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id.Subject != "ops-bot" {
		t.Errorf("Identity.Subject: got %q, want ops-bot", id.Subject)
	}
}

// ----- extractBearerToken -----

func TestExtractBearerToken(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer abc")
		tok, err := extractBearerToken(r)
		if err != nil || tok != "abc" {
			t.Errorf("got tok=%q err=%v", tok, err)
		}
	})
	t.Run("missing header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := extractBearerToken(r); !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("want ErrMissingCredentials, got %v", err)
		}
	})
	t.Run("wrong scheme", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Basic zzz")
		if _, err := extractBearerToken(r); !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("want ErrMissingCredentials, got %v", err)
		}
	})
	t.Run("empty token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer    ")
		if _, err := extractBearerToken(r); !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("want ErrMissingCredentials, got %v", err)
		}
	})
}

// ----- Middleware: writes 401 for missing creds on non-anonymous paths -----

func TestMiddleware_Unauthenticated401(t *testing.T) {
	p := NewStaticProvider("k")
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called for unauthenticated request")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content-type: got %q", got)
	}
}

// ----- Middleware: invalid credentials 401 -----

func TestMiddleware_InvalidCreds401(t *testing.T) {
	p := NewStaticProvider("correct")
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not run on bad creds")
	}))
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}
