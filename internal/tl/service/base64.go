package service

import (
	"encoding/base64"
	"fmt"
)

// decodeB64 decodes s using the named flavor ("std" or "url"),
// preserving error messages that distinguish them.
func decodeB64(flavor, s string) ([]byte, error) {
	var enc *base64.Encoding
	switch flavor {
	case "std":
		enc = base64.StdEncoding
	case "url":
		enc = base64.RawURLEncoding
	default:
		return nil, fmt.Errorf("service: unknown base64 flavor %q", flavor)
	}
	// Many callers pass padded / unpadded inputs; try strict first,
	// then unpadded as a fallback for URL-safe encoding.
	if raw, err := enc.DecodeString(s); err == nil {
		return raw, nil
	}
	if flavor == "std" {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return base64.URLEncoding.DecodeString(s)
}
