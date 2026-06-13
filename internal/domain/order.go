package domain

import (
	"fmt"
	"time"
)

// ChallengeType enumerates the domain-control challenge mechanisms a
// certificate provider can demand. Mirrors the V2 spec's
// `ChallengeInfo.type` enum (spec/api-spec-v2.yaml §ChallengeInfo:
// DNS_01 | HTTP_01).
type ChallengeType string

// Challenge types. Values match RFC 8555 challenge identifiers in the
// wire casing the V2 spec uses.
const (
	ChallengeTypeDNS01  ChallengeType = "DNS_01"
	ChallengeTypeHTTP01 ChallengeType = "HTTP_01"
)

// IsValid reports whether the challenge type is recognized.
func (t ChallengeType) IsValid() bool {
	switch t {
	case ChallengeTypeDNS01, ChallengeTypeHTTP01:
		return true
	default:
		return false
	}
}

// Challenge is a single domain-control challenge the domain owner must
// satisfy by publishing an artifact (a DNS TXT record or an HTTP
// resource) in the zone or site they control. Challenges are relayed
// to the owner verbatim — ANS never creates DNS records or serves
// challenge files on the owner's behalf; the pending-registration and
// renewal responses carry everything the owner needs to publish them
// themselves.
//
// Challenges originate from the certificate issuer port when a
// certificate order is created (`ServerCertificateIssuer.CreateOrder`).
// For the in-process self-signed CA the tokens are self-issued; for an
// external ACME CA (e.g. Let's Encrypt) the token and key
// authorization come from the provider's order and the DNS record
// value is the provider-computed digest.
type Challenge struct {
	// Type selects the verification mechanism.
	Type ChallengeType `json:"type"`

	// Token is the opaque challenge token issued by the certificate
	// provider (or self-issued by the RA when it is its own CA).
	Token string `json:"token"`

	// KeyAuthorization binds the token to the issuing account's key
	// per RFC 8555 §8.1 (token || "." || base64url(JWK thumbprint)).
	// Empty for self-issued challenges, which have no account binding.
	KeyAuthorization string `json:"keyAuthorization,omitempty"`

	// DNSRecordName overrides the TXT record name for DNS challenges.
	// Empty means the RFC 8555 default `_acme-challenge.<fqdn>`.
	// Non-ACME providers with proprietary DV record names set this.
	DNSRecordName string `json:"dnsRecordName,omitempty"`

	// DNSRecordValue overrides the TXT record value for DNS
	// challenges. ACME providers require
	// base64url(SHA-256(keyAuthorization)); self-issued challenges
	// publish the raw token. Empty means the raw token.
	DNSRecordValue string `json:"dnsRecordValue,omitempty"`

	// HTTPPath overrides the HTTP challenge path. Empty means the
	// RFC 8555 default `/.well-known/acme-challenge/<token>`.
	HTTPPath string `json:"httpPath,omitempty"`
}

// EffectiveDNSRecordName returns the TXT record name the owner must
// publish for a DNS_01 challenge, applying the RFC 8555 default when
// the provider didn't override it.
func (c Challenge) EffectiveDNSRecordName(fqdn string) string {
	if c.DNSRecordName != "" {
		return c.DNSRecordName
	}
	return "_acme-challenge." + fqdn
}

// EffectiveDNSRecordValue returns the TXT record value the owner must
// publish for a DNS_01 challenge. Defaults to the raw token for
// self-issued challenges.
func (c Challenge) EffectiveDNSRecordValue() string {
	if c.DNSRecordValue != "" {
		return c.DNSRecordValue
	}
	return c.Token
}

// EffectiveHTTPPath returns the URL path (under the agent's FQDN) the
// owner must serve the challenge content from for an HTTP_01
// challenge, applying the RFC 8555 default when the provider didn't
// override it.
func (c Challenge) EffectiveHTTPPath() string {
	if c.HTTPPath != "" {
		return c.HTTPPath
	}
	return "/.well-known/acme-challenge/" + c.Token
}

// ExpectedHTTPContent returns the body the owner must serve at the
// HTTP challenge path: the key authorization when the provider binds
// the token to an account key (RFC 8555 §8.3), otherwise the raw
// token.
func (c Challenge) ExpectedHTTPContent() string {
	if c.KeyAuthorization != "" {
		return c.KeyAuthorization
	}
	return c.Token
}

// OrderState is the lifecycle of a certificate order. It is tracked
// on the order itself, never on the agent lifecycle — `AgentLifecycle
// Status` stays exactly as the V2 spec defines it, and views like
// `RegistrationPending.status` (PENDING_CERTS) and `AgentStatus.phase`
// (CERTIFICATE_ISSUANCE) are derived from (agent status × order
// state).
type OrderState string

// Order states. PENDING means challenges are issued and awaiting
// domain validation; ISSUING means validation passed and the provider
// is finalizing asynchronously; COMPLETED and FAILED are terminal.
const (
	OrderStatePending   OrderState = "PENDING"
	OrderStateIssuing   OrderState = "ISSUING"
	OrderStateCompleted OrderState = "COMPLETED"
	OrderStateFailed    OrderState = "FAILED"
)

// CertificateOrder tracks a certificate issuance order and the
// domain-control challenges attached to it.
//
// Two shapes exist:
//
//   - Provider order (CSR path): created by the configured
//     `ServerCertificateIssuer` port. OrderRef is the provider-opaque
//     handle (an ACME order URL for ACME providers, an internal id for
//     the self-signed CA) used to finalize the order after the owner
//     satisfies a challenge.
//   - Self-issued validation order (BYOC path): no certificate is
//     being issued, but domain control must still be proven before the
//     registration advances. OrderRef is empty and the challenges are
//     RA-issued.
type CertificateOrder struct {
	OrderRef   string      `json:"orderRef,omitempty"`
	State      OrderState  `json:"state,omitempty"`
	Challenges []Challenge `json:"challenges,omitempty"`
	ExpiresAt  time.Time   `json:"expiresAt,omitzero"`
}

// NewSelfIssuedOrder builds the BYOC-path validation order from a
// pair of RA-generated tokens. The DNS record value and HTTP content
// default to the raw tokens (no account-key binding).
func NewSelfIssuedOrder(dns01Token, http01Token string, expiresAt time.Time) CertificateOrder {
	return CertificateOrder{
		State: OrderStatePending,
		Challenges: []Challenge{
			{Type: ChallengeTypeDNS01, Token: dns01Token},
			{Type: ChallengeTypeHTTP01, Token: http01Token},
		},
		ExpiresAt: expiresAt,
	}
}

// IsZero reports whether the order is unset — true for registrations
// that predate order persistence.
func (o *CertificateOrder) IsZero() bool {
	return o.OrderRef == "" && o.State == "" && len(o.Challenges) == 0 && o.ExpiresAt.IsZero()
}

// ChallengeOfType returns the first challenge of the given type.
func (o *CertificateOrder) ChallengeOfType(t ChallengeType) (Challenge, bool) {
	for _, c := range o.Challenges {
		if c.Type == t {
			return c, true
		}
	}
	return Challenge{}, false
}

// IsExpired reports whether the order's challenge window has elapsed
// without the order reaching a terminal state.
func (o *CertificateOrder) IsExpired(now time.Time) bool {
	if o.ExpiresAt.IsZero() {
		return false
	}
	return now.After(o.ExpiresAt) && o.State != OrderStateCompleted && o.State != OrderStateFailed
}

// MarkIssuing transitions PENDING → ISSUING: domain validation passed
// and the provider accepted the finalize request but has not produced
// a certificate yet. Idempotent for re-driven verify-acme calls (an
// ISSUING order stays ISSUING).
func (o *CertificateOrder) MarkIssuing() error {
	if o.State == OrderStateIssuing {
		return nil
	}
	if o.State != OrderStatePending {
		return NewInvalidStateError(
			"INVALID_ORDER_TRANSITION",
			fmt.Sprintf("cannot mark order ISSUING from state %s", o.State),
		)
	}
	o.State = OrderStateIssuing
	return nil
}

// MarkCompleted transitions PENDING|ISSUING → COMPLETED: the
// certificate landed (or, for a BYOC validation order, domain control
// was proven).
func (o *CertificateOrder) MarkCompleted() error {
	if o.State != OrderStatePending && o.State != OrderStateIssuing {
		return NewInvalidStateError(
			"INVALID_ORDER_TRANSITION",
			fmt.Sprintf("cannot mark order COMPLETED from state %s", o.State),
		)
	}
	o.State = OrderStateCompleted
	return nil
}

// MarkFailed transitions PENDING|ISSUING → FAILED: the provider
// reported a terminal order failure (e.g. an ACME order moved to
// `invalid`). A failed order cannot be retried — the operator submits
// a new registration or renewal.
func (o *CertificateOrder) MarkFailed() error {
	if o.State != OrderStatePending && o.State != OrderStateIssuing {
		return NewInvalidStateError(
			"INVALID_ORDER_TRANSITION",
			fmt.Sprintf("cannot mark order FAILED from state %s", o.State),
		)
	}
	o.State = OrderStateFailed
	return nil
}
