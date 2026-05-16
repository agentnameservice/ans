package did

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/godaddy/ans/internal/domain"
)

// selectVerificationMethodJWK picks the active verification method
// from the DID document and returns its public key in JWK form.
//
// Selection order per anchor-0b-did.md §2:
//  1. Methods referenced from the assertionMethod array (used to
//     sign registration events).
//  2. If none, methods referenced from authentication.
//  3. Among candidates, choose the one with the most recent
//     updated/created timestamp; ties broken lexicographically by
//     id so the choice is deterministic.
//
// Verification method references can be either embedded objects or
// fragment IDs pointing into the document's verificationMethod
// array. Both shapes are handled.
func selectVerificationMethodJWK(doc *didDocument) ([]byte, error) {
	candidates := collectByReferenceList(doc, doc.AssertionMethod)
	if len(candidates) == 0 {
		candidates = collectByReferenceList(doc, doc.Authentication)
	}
	if len(candidates) == 0 {
		// Fall back to the first verificationMethod entry the
		// document declares, if any. A document with no
		// verificationMethod at all is unusable.
		if len(doc.VerificationMethod) == 0 {
			return nil, domain.NewValidationError(
				"DID_NO_VERIFICATION_METHOD",
				"DID document has no usable verification method",
			)
		}
		candidates = doc.VerificationMethod
	}

	chosen := pickMostRecent(candidates)
	jwk, err := verificationMethodToJWK(chosen)
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

// collectByReferenceList resolves a list of verification-method
// references into concrete verificationMethod objects. References
// are either string fragment IDs (e.g. "#key-1") or embedded
// objects.
func collectByReferenceList(doc *didDocument, refs []json.RawMessage) []verificationMethod {
	out := make([]verificationMethod, 0, len(refs))
	for _, raw := range refs {
		// Try string first (fragment reference).
		var asString string
		if err := json.Unmarshal(raw, &asString); err == nil {
			if vm := findVerificationMethod(doc, asString); vm != nil {
				out = append(out, *vm)
			}
			continue
		}
		// Otherwise, embedded object.
		var vm verificationMethod
		if err := json.Unmarshal(raw, &vm); err == nil && vm.ID != "" {
			out = append(out, vm)
		}
	}
	return out
}

// findVerificationMethod resolves a verification-method reference
// (full URI or fragment ID) against doc.VerificationMethod.
func findVerificationMethod(doc *didDocument, reference string) *verificationMethod {
	wantSuffix := reference
	if strings.HasPrefix(reference, "#") {
		wantSuffix = reference[1:]
	}
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == reference {
			return vm
		}
		if idx := strings.Index(vm.ID, "#"); idx >= 0 && vm.ID[idx+1:] == wantSuffix {
			return vm
		}
	}
	return nil
}

// pickMostRecent selects the candidate with the newest
// updated/created timestamp; ties broken lexicographically by id.
func pickMostRecent(candidates []verificationMethod) verificationMethod {
	if len(candidates) == 1 {
		return candidates[0]
	}
	sorted := make([]verificationMethod, len(candidates))
	copy(sorted, candidates)
	sort.SliceStable(sorted, func(i, j int) bool {
		ti := timestampOf(sorted[i])
		tj := timestampOf(sorted[j])
		if ti != tj {
			return ti > tj // descending: newest first
		}
		return sorted[i].ID < sorted[j].ID
	})
	return sorted[0]
}

// timestampOf returns the verification method's effective
// timestamp string for comparison; updated wins over created.
func timestampOf(vm verificationMethod) string {
	if vm.Updated != "" {
		return vm.Updated
	}
	return vm.Created
}

// verificationMethodToJWK converts a verification method's public
// key to the JWK byte form ANS-0 IdentityClaim expects. Three
// encodings are admitted per anchor-0b-did.md §3.2 step 8:
//   - publicKeyJwk: pass through after re-canonicalizing the JSON
//     so the bytes are stable for downstream hashing.
//   - publicKeyMultibase: not yet supported; returns
//     DID_KEY_MULTIBASE_NOT_IMPLEMENTED. Slice 2.1 will add
//     multicodec key-type prefix decoding for the four common
//     types (Ed25519, X25519, secp256k1, P-256).
//   - publicKeyPem: not yet supported; returns
//     DID_KEY_PEM_NOT_IMPLEMENTED.
//
// A verification method that supplies none of the three forms is
// rejected with DID_KEY_MISSING.
func verificationMethodToJWK(vm verificationMethod) ([]byte, error) {
	switch {
	case len(vm.PublicKeyJwk) > 0:
		// Re-canonicalize through json.Marshal so the byte form is
		// stable regardless of how the source serialized.
		var jwkValue interface{}
		if err := json.Unmarshal(vm.PublicKeyJwk, &jwkValue); err != nil {
			return nil, domain.NewValidationError(
				"DID_KEY_BAD_JWK",
				"verification method's publicKeyJwk is not valid JSON",
			)
		}
		out, err := json.Marshal(jwkValue)
		if err != nil {
			return nil, domain.NewInternalError(
				"DID_KEY_REMARSHAL", "remarshal publicKeyJwk", err,
			)
		}
		return out, nil
	case vm.PublicKeyMultib != "":
		return nil, domain.NewValidationError(
			"DID_KEY_MULTIBASE_NOT_IMPLEMENTED",
			fmt.Sprintf("publicKeyMultibase decoding not implemented in this slice (vm id=%s)", vm.ID),
		)
	case vm.PublicKeyPem != "":
		return nil, domain.NewValidationError(
			"DID_KEY_PEM_NOT_IMPLEMENTED",
			fmt.Sprintf("publicKeyPem decoding not implemented in this slice (vm id=%s)", vm.ID),
		)
	default:
		return nil, domain.NewValidationError(
			"DID_KEY_MISSING",
			fmt.Sprintf("verification method id=%s carries no publicKey* field", vm.ID),
		)
	}
}
