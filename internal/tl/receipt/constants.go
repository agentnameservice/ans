// Package receipt implements SCITT-style COSE_Sign1 transparency-log
// receipts for the ANS TL.
//
// The wire format mirrors the reference TL so an external verifier
// built against the reference can consume ours unchanged.
// Label constants and encoding rules come from IANA's COSE header
// registry, RFC 8152 (COSE), RFC 8392 (CWT), and draft-ietf-cose-
// merkle-tree-proofs-18 (the SCITT VDS/VDP draft).
//
// What a receipt contains:
//
//	COSE_Sign1 array, tagged with CBOR tag 18:
//	  [
//	    protected_header : bstr of CBOR{alg, kid, vds, cwt-claims{iss, iat}},
//	    unprotected_header : map{vdp: {treeSize, leafIndex, path, rootHash}},
//	    payload  : bstr of the JCS-canonical event bytes (attached),
//	    signature : ES256 IEEE P1363 over Sig_structure1,
//	  ]
//
// The attached payload (not detached) is deliberate: without the
// event bytes in the receipt, a verifier can't bind the receipt to
// the Agent Card data it's trying to attest to. Every other element
// of the leaf hash is in the signed envelope and thus in the
// attached payload.
package receipt

// COSE header labels (IANA COSE header registry).
const (
	labelAlg         = 1
	labelContentType = 3
	labelKID         = 4
	labelCWTClaims   = 15
)

// Verifiable Data Structure labels (draft-ietf-cose-merkle-tree-proofs-18).
const (
	labelVDS = 395 // Verifiable Data Structure identifier (in protected header)
	labelVDP = 396 // Verifiable Data Structure Proofs (in unprotected header)
)

// Algorithm identifier (RFC 8152).
const algES256 = -7

// Verifiable Data Structure type identifier.
const vdsRFC9162SHA256 = 1

// CWT claims labels (RFC 8392).
const (
	cwtIss = 1 // Issuer (string) — the TL origin name
	cwtIat = 6 // Issued At (unix seconds)
)

// SCITT inclusion-proof map keys (inside the VDP value).
const (
	inclusionProofTreeSize  = -1
	inclusionProofLeafIndex = -2
	inclusionProofHashPath  = -3
	inclusionProofRootHash  = -4
)

// MediaType is the Content-Type header value the TL returns for
// COSE_Sign1 receipts. Matches the SCITT draft's recommended type.
const MediaType = "application/scitt-receipt+cose"
