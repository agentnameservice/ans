package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	eventv1 "github.com/godaddy/ans/internal/tl/event/v1"
)

// V1 events coexist with V2 events on the RA→TL path: the outbox row
// carries a `schemaVersion` column ("V1" or "V2"), the worker routes
// on it, and the TL dispatches to the V1 or V2 ingest lane. These
// helpers are the V1 mirror of baseInnerEvent + signAndMarshalPayload
// + enqueueTLEvent in this package.
//
// Two things differ from the V2 helpers:
//
//   1. The inner event is `eventv1.Event` (different enum, different
//      attestations shape — singleton `identityCert`/`serverCert` +
//      rotation arrays `validIdentityCerts[]`, `dnsRecordsProvisioned`
//      as `map[string]string`).
//   2. The outbox row is stamped with `eventv1.SchemaVersion` so the
//      worker POSTs to `/v1/internal/agents/event` on the TL.
//
// Everything else — producer signing, JCS canonicalization, retry
// invariants — is identical, so we reuse `signDetachedJWS` and the
// same `OutboxPayload` shape.

// baseInnerV1Event mirrors baseInnerEvent for the V1 schema: same
// identity + timestamps, different inner-event type.
func (s *RegistrationService) baseInnerV1Event(
	reg *domain.AgentRegistration, et eventv1.Type, now time.Time,
) *eventv1.Event {
	raID := ""
	if s.signer != nil {
		raID = s.signer.RaID
	}
	return &eventv1.Event{
		AnsID:     reg.AgentID,
		AnsName:   reg.AnsName.String(),
		EventType: et,
		Agent: &eventv1.Agent{
			Host:    reg.FQDN(),
			Name:    reg.Details.DisplayName,
			Version: reg.AnsName.Version().String(),
		},
		RaID:      raID,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		Timestamp: now.UTC().Format(time.RFC3339),
	}
}

// signAndMarshalPayloadV1 is the V1 mirror of signAndMarshalPayload:
// JCS-canonicalize the V1 inner event, sign with the RA's producer
// key, and marshal the {innerEventCanonical, producerSignature} pair
// into the outbox-row payload.
//
// Same replay invariant applies: retries by the worker MUST send
// these exact bytes verbatim, so the signature is computed once here
// and persisted.
func (s *RegistrationService) signAndMarshalPayloadV1(
	ctx context.Context, inner *eventv1.Event, now time.Time,
) ([]byte, error) {
	innerCanonical, err := eventv1.CanonicalizeEvent(inner)
	if err != nil {
		return nil, fmt.Errorf("canonicalize V1 inner event: %w", err)
	}
	var producerSig string
	if s.signer != nil {
		producerSig, err = anscrypto.SignDetachedJWS(
			ctx, s.signer.KeyManager, s.signer.KeyID,
			anscrypto.JWSProtectedHeader{
				Typ:       "JWT",
				Timestamp: now.Unix(),
				RAID:      s.signer.RaID,
			},
			innerCanonical,
		)
		if err != nil {
			return nil, fmt.Errorf("sign V1 outbox event: %w", err)
		}
	}
	return json.Marshal(OutboxPayload{
		InnerEventCanonical: json.RawMessage(innerCanonical),
		ProducerSignature:   producerSig,
	})
}

// enqueueTLEventV1 is the V1 chokepoint for writing a signed event to
// the outbox. Stamps the row with `eventv1.SchemaVersion` so the
// worker routes to the V1 TL ingest lane.
func (s *RegistrationService) enqueueTLEventV1(
	ctx context.Context, eventTypeTag string,
	reg *domain.AgentRegistration, inner *eventv1.Event, now time.Time,
) error {
	if s.outbox == nil {
		return nil
	}
	payload, err := s.signAndMarshalPayloadV1(ctx, inner, now)
	if err != nil {
		return err
	}
	if _, err := s.outbox.Enqueue(ctx, eventTypeTag, reg.AgentID, eventv1.SchemaVersion, payload, now); err != nil {
		return err
	}
	return nil
}

// v1RevokedCertList maps domain StoredCertificate → V1 rotation-array
// cert info. Used by the V1 revoke emit path where the envelope
// records which certs the operator should tear down. V1 uses the
// rotation-array shape (`validIdentityCerts[]`) for cert lists —
// even in the single-element case — matching the reference V1
// RA-attestations schema.
//
// A fingerprint failure on any cert is propagated rather than
// silently dropping that cert from the envelope: a missing
// fingerprint in an AGENT_REVOKED leaf would leave offline verifiers
// unable to mark that cert untrusted, which is the exact failure
// mode revocation exists to prevent. Mirrors the V2 path's
// behaviour in buildAgentRegisteredEvent / Revoke.
func v1RevokedCertList(certs []*domain.StoredCertificate) ([]eventv1.CertificateInfoExtended, error) {
	out := make([]eventv1.CertificateInfoExtended, 0, len(certs))
	for _, c := range certs {
		fp, err := fingerprintOf(c.CertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("v1RevokedCertList: fingerprint cert csr=%s: %w", c.CSRID, err)
		}
		out = append(out, eventv1.CertificateInfoExtended{
			Fingerprint: fp,
			CertType:    "X509-OV-CLIENT",
			NotAfter:    c.ExpirationTimestamp.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// buildAgentRegisteredV1Event assembles the V1 AGENT_REGISTERED
// envelope emitted on verify-dns ACTIVE transition. Byte-for-byte
// shape parity with the reference V1 RA-attestations schema:
//
//   - `dnsRecordsProvisioned` as map[name]data (V1 lossy shape — a
//     V2 typed-array lands in a single entry per name; collisions
//     use last-wins).
//   - `domainValidation` = the ACME method that satisfied the
//     domain-control gate ("ACME-DNS-01" / "ACME-HTTP-01"), recorded
//     on the certificate order at gate-pass time. Omitted for
//     registrations that predate recording. (The reference emits a
//     constant "ACME-DNS-01" here; its schema enumerates all three
//     method tokens, so the faithful value is shape-compatible.)
//   - `identityCert` singleton — the primary active identity cert.
//   - `validIdentityCerts[]` rotation array — every currently valid
//     identity cert (includes the primary). Present even with one
//     cert to match reference behavior.
//   - `serverCert` singleton + `validServerCerts[]` rotation array
//     when the operator supplied a BYOC cert at registration.
//   - `metadataHashes` per-protocol, uppercased keys (A2A, MCP, ...).
//
// Populated from the same sources the V2 `buildAgentActiveEvent`
// reads so V1 and V2 emits describe the same underlying agent
// state, just in different envelope shapes.
func (s *RegistrationService) buildAgentRegisteredV1Event(
	ctx context.Context, reg *domain.AgentRegistration,
	expected []domain.ExpectedDNSRecord, now time.Time,
) (*eventv1.Event, error) {
	inner := s.baseInnerV1Event(reg, eventv1.TypeAgentRegistered, now)

	// Provisioned DNS records — V1's `map[name]data` shape. When an
	// operator publishes two records at the same owner name (e.g.
	// two TXTs), V1 can only keep one. We preserve the last value
	// encountered; this is a known V1 lossiness the V2 shape fixes.
	dnsMap := make(map[string]string, len(expected))
	for _, r := range expected {
		dnsMap[r.Name] = r.Value
	}

	// Identity certs: the full set of currently-valid certs. The
	// singleton `identityCert` is the first one (there's typically
	// one at registration time; rotation adds more). The
	// `validIdentityCerts` array carries every valid cert including
	// the primary — matches the reference presence rule.
	identityCerts, err := s.certs.FindIdentityCertificatesByAgent(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}
	var primaryIdentity *eventv1.CertificateInfo
	validIdentity := make([]eventv1.CertificateInfoExtended, 0, len(identityCerts))
	for _, c := range identityCerts {
		if !c.IsValid(now) {
			continue
		}
		fp, ferr := fingerprintOf(c.CertificatePEM)
		if ferr != nil {
			return nil, ferr
		}
		if primaryIdentity == nil {
			primaryIdentity = &eventv1.CertificateInfo{
				Fingerprint: fp,
				CertType:    "X509-OV-CLIENT",
			}
		}
		validIdentity = append(validIdentity, eventv1.CertificateInfoExtended{
			Fingerprint: fp,
			CertType:    "X509-OV-CLIENT",
			NotAfter:    c.ExpirationTimestamp.UTC().Format(time.RFC3339),
		})
	}

	// Server cert (BYOC or CSR-signed): folded into the terminal V1
	// attestation. A transient store error must abort — this leaf is
	// signed and appended to the append-only log, so swallowing it
	// would emit a permanently wrong attestation from a recoverable
	// fault.
	var primaryServer *eventv1.CertificateInfo
	var validServer []eventv1.CertificateInfoExtended
	byocCert, berr := s.loadServerCert(ctx, reg.AgentID)
	if berr != nil {
		return nil, berr
	}
	if byocCert != nil {
		fp := "SHA256:" + byocCert.Fingerprint
		primaryServer = &eventv1.CertificateInfo{
			Fingerprint: fp,
			CertType:    "X509-DV-SERVER",
		}
		validServer = []eventv1.CertificateInfoExtended{{
			Fingerprint: fp,
			CertType:    "X509-DV-SERVER",
			NotAfter:    byocCert.ValidToTimestamp.UTC().Format(time.RFC3339),
		}}
	}

	// `expiresAt` required at event level per the reference V1 spec —
	// min(notAfter) across attested identity + server certs.
	inner.ExpiresAt = agentCertExpiry(identityCerts, byocCert, now)

	// `domainValidation` mirrors the V2 builder: the method that
	// actually satisfied the gate, recorded on the order at gate-pass
	// time; omitted (never guessed) for registrations that predate
	// recording.
	inner.Attestations = &eventv1.Attestations{
		DNSRecordsProvisioned: dnsMap,
		DomainValidation:      reg.CertOrder.VerifiedChallenge.ACMEMethodToken(),
		IdentityCert:          primaryIdentity,
		ServerCert:            primaryServer,
		ValidIdentityCerts:    validIdentity,
		ValidServerCerts:      validServer,
		MetadataHashes:        metadataHashesFromEndpoints(reg.Endpoints),
	}
	return inner, nil
}

// buildAgentRevokedV1Event assembles the V1 AGENT_REVOKED envelope
// emitted on revoke. Includes:
//
//   - `revokedAt` timestamp (RFC3339 UTC).
//   - `revocationReasonCode` from the caller's stated reason.
//   - `dnsRecordsProvisioned` — the records the operator now needs
//     to tear down (same set that was attested at ACTIVE).
//   - `validIdentityCerts[]` — the identity certs being revoked,
//     so offline verifiers can mark their fingerprints untrusted.
//   - `validServerCerts[]` — the BYOC server cert if any.
//
// The reason + timestamp live on the inner event fields; the cert
// + DNS context lives in attestations.
func (s *RegistrationService) buildAgentRevokedV1Event(
	reg *domain.AgentRegistration,
	certs []*domain.StoredCertificate, reason domain.RevocationReason, now time.Time,
) (*eventv1.Event, error) {
	inner := s.baseInnerV1Event(reg, eventv1.TypeAgentRevoked, now)
	inner.RevokedAt = now.UTC().Format(time.RFC3339)
	inner.RevocationReasonCode = string(reason)

	// Caller (RegistrationService.Revoke) has already loaded
	// reg.Endpoints before invoking us, so ComputeRequiredDNSRecords
	// sees the full record set (including per-endpoint metadata
	// records). If it didn't, we'd get back an empty list and the
	// revoke envelope would ship with no DNS tear-down guidance.
	expected := s.ComputeRequiredDNSRecords(reg)
	dnsMap := make(map[string]string, len(expected))
	for _, r := range expected {
		dnsMap[r.Name] = r.Value
	}

	// BYOC server cert at time of revocation. Caller (Revoke) has
	// already hydrated reg.ServerCert before invoking us so we can
	// surface the cert here even though it's been marked revoked
	// in storage by now (FindLatestValid wouldn't return it).
	var validServer []eventv1.CertificateInfoExtended
	if reg.ServerCert != nil {
		validServer = []eventv1.CertificateInfoExtended{{
			Fingerprint: "SHA256:" + reg.ServerCert.Fingerprint,
			CertType:    "X509-DV-SERVER",
			NotAfter:    reg.ServerCert.ValidToTimestamp.UTC().Format(time.RFC3339),
		}}
	}

	// `expiresAt` is required at event level per the reference V1
	// spec, including on terminal events. Use the certs' original
	// notAfter values (post-revocation status filter would skip them).
	var minExpiry time.Time
	for _, c := range certs {
		if c.ExpirationTimestamp.IsZero() {
			continue
		}
		if minExpiry.IsZero() || c.ExpirationTimestamp.Before(minExpiry) {
			minExpiry = c.ExpirationTimestamp
		}
	}
	if reg.ServerCert != nil && !reg.ServerCert.ValidToTimestamp.IsZero() {
		if minExpiry.IsZero() || reg.ServerCert.ValidToTimestamp.Before(minExpiry) {
			minExpiry = reg.ServerCert.ValidToTimestamp
		}
	}
	if !minExpiry.IsZero() {
		inner.ExpiresAt = minExpiry.UTC().Format(time.RFC3339)
	}

	revokedCerts, err := v1RevokedCertList(certs)
	if err != nil {
		return nil, err
	}
	inner.Attestations = &eventv1.Attestations{
		DNSRecordsProvisioned: dnsMap,
		ValidIdentityCerts:    revokedCerts,
		ValidServerCerts:      validServer,
	}
	return inner, nil
}
