package crypto

import (
	"crypto"
	"crypto/rsa"
)

// rsaVerifyPKCS1v15 verifies an RSA PKCS#1 v1.5 signature over a
// pre-computed SHA-256 digest. Returns nil on success.
func rsaVerifyPKCS1v15(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}
