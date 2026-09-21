package service

import (
	"encoding/json"
	"fmt"
	"github.com/agentnameservice/ans/internal/domain"
	"time"
)

// envelopeWrapper is the schema-agnostic view of a stored envelope
// JSON. Both V1 and V2 share the outer wrapper shape
// (`payload` / `schemaVersion` / `signature` / `status`), so we
// parse at that level and treat `payload` as opaque JSON. The
// downstream TransparencyLog response echoes `payload` verbatim and
// sets `schemaVersion` so clients pick the right parser for the
// inner event.
type envelopeWrapper struct {
	SchemaVersion string          `json:"schemaVersion,omitempty"`
	Signature     string          `json:"signature,omitempty"`
	Status        string          `json:"status,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}

// parseEnvelopeWrapper parses the minimum fields needed to build a
// TransparencyLog response. Returns an error only on malformed JSON
// — missing fields are permitted (the wrapper is tolerant; missing
// `signature` for instance just yields an empty TL attestation on
// the response).
func parseEnvelopeWrapper(raw string) (*envelopeWrapper, error) {
	var w envelopeWrapper
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return nil, fmt.Errorf("service: parse envelope wrapper: %w", err)
	}
	var payload struct {
		Producer struct {
			Event struct {
				ExpiresAt    string `json:"expiresAt"`
				Attestations struct {
					Identity       []certInfoView `json:"identityCerts"`
					Server         []certInfoView `json:"serverCerts"`
					LegacyIdentity []certInfoView `json:"validIdentityCerts"`
					LegacyServer   []certInfoView `json:"validServerCerts"`
				} `json:"attestations"`
			} `json:"event"`
		} `json:"producer"`
	}
	if len(w.Payload) > 0 {
		if err := json.Unmarshal(w.Payload, &payload); err != nil {
			return nil, fmt.Errorf("decode attested certificate dates: %w", err)
		}
		event := payload.Producer.Event
		if _, err := domain.ParseAttestedExpiry(event.ExpiresAt); err != nil {
			return nil, err
		}
		for _, family := range [][]certInfoView{event.Attestations.Identity, event.Attestations.Server, event.Attestations.LegacyIdentity, event.Attestations.LegacyServer} {
			for _, cert := range family {
				if _, err := domain.ParseAttestedExpiry(cert.NotAfter); err != nil {
					return nil, err
				}
			}
		}
	}
	return &w, nil
}

// certExpiresAt returns the effective expiry for badge-status
// derivation: the earlier of the latest identity-cert and server-cert
// notAfter timestamps attested on the event. This is what the TL
// compares against `now` to flip badge status to WARNING (30 days
// before) / EXPIRED (after).
//
// The function is schema-agnostic enough to drill through both
// V1 and V2 envelopes:
//
//   - V1 carries certs under `attestations.identityCert` +
//     `attestations.validIdentityCerts[]` (singleton + rotation array)
//     and `attestations.serverCert` + `validServerCerts[]`.
//   - V2 collapses both shapes into `attestations.identityCerts[]` and
//     `attestations.serverCerts[]` arrays.
//
// Each family remains usable while at least one allowed certificate is
// unexpired. Expiry of an old overlap certificate must not expire its
// replacement. Returns a zero time when no attested cert is
// present (revocation events, deprecation events). Callers treat
// zero as "no expiry to enforce, badge stays ACTIVE".
func (w *envelopeWrapper) certExpiresAt() time.Time {
	if len(w.Payload) == 0 {
		return time.Time{}
	}
	var payload struct {
		Producer struct {
			Event struct {
				ExpiresAt    string `json:"expiresAt"`
				Attestations struct {
					// V2 shape: unified arrays.
					IdentityCerts []certInfoView `json:"identityCerts"`
					ServerCerts   []certInfoView `json:"serverCerts"`
					// V1 shape: singleton + rotation arrays.
					IdentityCert       *certInfoView  `json:"identityCert"`
					ValidIdentityCerts []certInfoView `json:"validIdentityCerts"`
					ServerCert         *certInfoView  `json:"serverCert"`
					ValidServerCerts   []certInfoView `json:"validServerCerts"`
				} `json:"attestations"`
			} `json:"event"`
		} `json:"producer"`
	}
	if err := json.Unmarshal(w.Payload, &payload); err != nil {
		return time.Time{}
	}

	attest := payload.Producer.Event.Attestations
	identity := attest.IdentityCerts
	identity = append(identity, attest.ValidIdentityCerts...)
	server := attest.ServerCerts
	server = append(server, attest.ValidServerCerts...)
	if len(identity) == 0 && attest.IdentityCert != nil {
		identity = append(identity, *attest.IdentityCert)
	}
	if len(server) == 0 && attest.ServerCert != nil {
		server = append(server, *attest.ServerCert)
	}
	fallback, _ := domain.ParseAttestedExpiry(payload.Producer.Event.ExpiresAt)
	var earliest time.Time
	for _, family := range [][]certInfoView{identity, server} {
		var latest time.Time
		for _, c := range family {
			t, err := domain.ParseAttestedExpiry(c.NotAfter)
			if err != nil || t.IsZero() {
				t = fallback
			}
			if t.After(latest) {
				latest = t
			}
		}
		if !latest.IsZero() && (earliest.IsZero() || latest.Before(earliest)) {
			earliest = latest
		}
	}
	if earliest.IsZero() {
		return fallback
	}
	return earliest
}

// certInfoView is the shared cert-attestation subset we need to
// derive expiry — `notAfter` is the only field that matters here.
// Shape matches both V1 `CertificateInfo` / `CertificateInfoExtended`
// and V2 `CertificateInfo`.
type certInfoView struct {
	NotAfter string `json:"notAfter"`
}
