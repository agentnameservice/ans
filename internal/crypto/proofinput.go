package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// IdentityProofPurpose is the domain-separation discriminator inside
// every identity proof signing input. An operator's identity keys
// also sign VCs, DIDComm, and application payloads; a purpose-tagged
// input can never verify as any of those (nor vice versa).
const IdentityProofPurpose = "ans:identity-proof:v1"

// IdentityProofInput is the ONE signing input in the identity proof
// system — the JSON object whose RFC 8785 (JCS) canonical bytes the
// registrant signs to prove key control. It binds the proof to:
//
//   - this identifier (anti-substitution),
//   - this identity object (identityId — anti-cross-use),
//   - this challenge round (nonce — anti-replay),
//   - this protocol (purpose — anti-cross-protocol-confusion),
//   - this RA deployment (raId — a signature minted against staging
//     can never replay against production),
//   - this scheme.
//
// The RA serves the encoded form (SigningInput) in the 202 response;
// clients sign it verbatim and never need a JCS implementation — the
// RA checks payload-equality before verifying any signature, so
// canonicalization-mismatch interop failures are structurally
// impossible.
type IdentityProofInput struct {
	Identifier string `json:"identifier"`
	IdentityID string `json:"identityId"`
	Nonce      string `json:"nonce"`
	Purpose    string `json:"purpose"`
	RaID       string `json:"raId"`
	Scheme     string `json:"scheme"`
}

// Canonical returns the JCS-canonical bytes of the proof input — the
// exact bytes a compact JWS over this input must carry as its payload.
func (in IdentityProofInput) Canonical() ([]byte, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("proofinput: marshal: %w", err)
	}
	return Canonicalize(raw)
}

// SigningInput returns the base64url (unpadded) encoding of the
// canonical bytes — the string served in the 202 challenge response.
// A compact JWS's payload segment MUST equal this string verbatim.
func (in IdentityProofInput) SigningInput() (string, error) {
	canonical, err := in.Canonical()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(canonical), nil
}
