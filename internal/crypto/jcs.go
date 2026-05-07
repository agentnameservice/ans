package crypto

import (
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize transforms arbitrary JSON input into RFC 8785 canonical
// form. Two semantically equal JSON values produce identical canonical
// byte sequences, which is what lets us sign JSON payloads deterministically.
func Canonicalize(jsonBytes []byte) ([]byte, error) {
	out, err := jsoncanonicalizer.Transform(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: canonicalize: %w", err)
	}
	return out, nil
}
