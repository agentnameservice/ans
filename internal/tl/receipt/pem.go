package receipt

import "encoding/pem"

// pemDecode returns the DER bytes of the first PEM block in s, or
// nil if s doesn't contain a well-formed PEM block. The verifier
// tolerates surrounding whitespace/newlines from config files and
// HTTP bodies.
func pemDecode(s string) []byte {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil
	}
	return block.Bytes
}
