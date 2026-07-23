package crypto_test

import (
	"encoding/base64"
	"strings"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

// TestDecodeStandardJWS_RejectsCrit pins RFC 7515 §4.1.11: this
// verifier implements no critical extensions, so any JWS bearing a
// crit header is rejected at decode — before key selection, before
// signature verification (design §5.5 third-party recipe).
func TestDecodeStandardJWS_RejectsCrit(t *testing.T) {
	t.Parallel()
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"ES256","kid":"did:web:a.com#k1","crit":["exp"],"exp":1}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	jws := header + "." + payload + ".c2ln"

	_, _, err := anscrypto.DecodeStandardJWS(jws)
	if err == nil || !strings.Contains(err.Error(), "critical header") {
		t.Fatalf("crit must be rejected, got %v", err)
	}
}
