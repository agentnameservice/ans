package domain

import (
	"net/url"
	"strings"
)

// AttestationPayload is the inner-payload value object the RA returns
// from GET /v2/ans/agents/{agentId}/attestation. It is what gets
// CBOR-encoded into the `payload` field of the outer COSE_Sign1.
//
// Field tags pin the CBOR key names byte-for-byte to the wire shape
// declared in spec/api-spec-v2.yaml § /ans/agents/{agentId}/attestation.
// Verifiers encode against these names; renaming a field is a wire-
// format breaking change.
//
// Why "Payload" not just "Attestation": the term "attestation" in
// this domain refers to the *signed* document (outer COSE_Sign1).
// The value type here is the unsigned payload that goes inside it —
// distinguishing the two prevents the very common bug of returning
// the raw struct from an HTTP handler instead of the signed bytes.
type AttestationPayload struct {
	Issuer                 string         `cbor:"iss"`
	Subject                string         `cbor:"sub"`
	DID                    string         `cbor:"did"`
	IssuedAt               int64          `cbor:"iat"`
	ExpiresAt              int64          `cbor:"exp"`
	IdentityCertSPKISHA256 []byte         `cbor:"identity_cert_spki_sha256"`
	ServerCertSPKISHA256   []byte         `cbor:"server_cert_spki_sha256"`
	DNS                    AttestationDNS `cbor:"dns"`
	TL                     AttestationTL  `cbor:"tl"`
	// TrustScheme is the optional TRAIN trust-scheme DNS name.
	// Omitted from the wire (omitempty) when the operator has not
	// configured one — the spec calls this out as the only optional
	// top-level field. All other zero-values are validation errors,
	// not omit-from-output.
	TrustScheme string `cbor:"trust_scheme,omitempty"`
}

// AttestationDNS bundles the DNS-verification evidence the RA's DNS
// adapter captured at registration / latest renewal time.
type AttestationDNS struct {
	VerifiedAt      int64    `cbor:"verified_at"`
	TLSARecords     [][]byte `cbor:"tlsa_records"`
	DNSSECValidated bool     `cbor:"dnssec_validated"`
}

// AttestationTL bundles the transparency-log binding for this
// registration. `Receipt` is the existing TL-signed SCITT COSE_Sign1
// receipt, fetched verbatim from the TL — the verifier's two-key
// check validates the outer attestation against the RA producer key
// and this embedded receipt against the TL root key.
type AttestationTL struct {
	LogURL   string `cbor:"log_url"`
	LeafHash []byte `cbor:"leaf_hash"`
	TreeSize uint64 `cbor:"tree_size"`
	Receipt  []byte `cbor:"receipt"`
}

// DIDForSubject returns the did:web identifier derived from a
// flat-FQDN subject. The transformation is the lossless mapping from
// the W3C DID Core spec: the FQDN becomes the method-specific id
// with `:` separators preserved. Subjects already containing a colon
// (an IPv6 address-form host, or a malformed input) are rejected
// upstream by NewAttestationPayload's host validation.
func DIDForSubject(subject string) string {
	return "did:web:" + subject
}

// NewAttestationPayload returns a validated AttestationPayload.
// `did` is derived from `subject` if left empty so callers can't
// accidentally publish an inconsistent (sub, did) pair on the wire.
//
// Validation is strict — every load-bearing field is required at
// construction time because the alternative is a 500 from the
// outermost handler with no actionable error message for the
// operator. We surface failures here with explicit CODE values the
// HTTP layer maps to RFC 7807 problem responses.
func NewAttestationPayload(p AttestationPayload) (AttestationPayload, error) {
	out := p

	if out.Issuer == "" {
		return AttestationPayload{}, NewValidationError("ATTESTATION_MISSING_ISS",
			"attestation: iss is required")
	}
	if _, err := url.Parse(out.Issuer); err != nil {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_ISS",
			"attestation: iss must parse as a URL: "+err.Error())
	}

	out.Subject = strings.ToLower(strings.TrimSpace(out.Subject))
	if out.Subject == "" {
		return AttestationPayload{}, NewValidationError("ATTESTATION_MISSING_SUB",
			"attestation: sub is required")
	}
	if err := validateAgentHost(out.Subject); err != nil {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_SUB",
			"attestation: sub must be a valid hostname: "+err.Error())
	}

	if out.DID == "" {
		out.DID = DIDForSubject(out.Subject)
	} else if !strings.HasPrefix(out.DID, "did:web:") {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_DID",
			"attestation: did must start with did:web:")
	}

	if out.IssuedAt <= 0 {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_IAT",
			"attestation: iat must be positive unix seconds")
	}
	if out.ExpiresAt <= out.IssuedAt {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_EXP",
			"attestation: exp must be greater than iat")
	}

	if len(out.IdentityCertSPKISHA256) != 32 {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_IDENTITY_SPKI",
			"attestation: identity_cert_spki_sha256 must be exactly 32 bytes")
	}
	if len(out.ServerCertSPKISHA256) != 32 {
		return AttestationPayload{}, NewValidationError("ATTESTATION_INVALID_SERVER_SPKI",
			"attestation: server_cert_spki_sha256 must be exactly 32 bytes")
	}

	if err := out.DNS.validate(); err != nil {
		return AttestationPayload{}, err
	}
	if err := out.TL.validate(); err != nil {
		return AttestationPayload{}, err
	}
	return out, nil
}

func (d AttestationDNS) validate() error {
	if d.VerifiedAt <= 0 {
		return NewValidationError("ATTESTATION_INVALID_DNS_VERIFIED_AT",
			"attestation: dns.verified_at must be positive unix seconds")
	}
	// TLSARecords may legitimately be empty when the agent uses
	// dnsRecordStyle=BADGE_TXT_ONLY (no TLSA published). Empty slice
	// is fine; nil-vs-empty distinction is preserved on the wire by
	// the CBOR encoder.
	return nil
}

func (t AttestationTL) validate() error {
	if t.LogURL == "" {
		return NewValidationError("ATTESTATION_MISSING_TL_LOG_URL",
			"attestation: tl.log_url is required")
	}
	if _, err := url.Parse(t.LogURL); err != nil {
		return NewValidationError("ATTESTATION_INVALID_TL_LOG_URL",
			"attestation: tl.log_url must parse as a URL: "+err.Error())
	}
	if len(t.LeafHash) != 32 {
		return NewValidationError("ATTESTATION_INVALID_TL_LEAF_HASH",
			"attestation: tl.leaf_hash must be exactly 32 bytes (SHA-256)")
	}
	if t.TreeSize == 0 {
		return NewValidationError("ATTESTATION_INVALID_TL_TREE_SIZE",
			"attestation: tl.tree_size must be positive")
	}
	if len(t.Receipt) == 0 {
		return NewValidationError("ATTESTATION_MISSING_TL_RECEIPT",
			"attestation: tl.receipt is required (embedded TL-signed COSE_Sign1)")
	}
	return nil
}
