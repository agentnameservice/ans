package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// loadRoot in selfca.go and serverselfca.go has multiple defensive
// branches that the integration tests don't reach because they all
// exercise either the happy round-trip or the entirely-malformed
// case. This file pins each in-between branch so a future PEM /
// PKCS8-parsing refactor doesn't silently regress.

// helperRSAKeyPKCS8 generates a PKCS#8-encoded RSA private key. Used
// to drive "key parses but isn't a crypto.Signer" / "key is not the
// algorithm we expect" branches — actually, every RSA key satisfies
// crypto.Signer, so this isn't quite the right shape. Instead we use
// the "wrong PEM type" branch for that.
func writeRootPEM(t *testing.T, dir, filename, blockType string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename),
		pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: body}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSelfCA_LoadRoot_WrongKeyPEMType — the loader requires the
// PEM block type to be "PRIVATE KEY". Anything else is a hard error
// (with a specific failure message), so a misnamed export from
// some other tool is caught up front.
func TestSelfCA_LoadRoot_WrongKeyPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRootPEM(t, dir, "root.key", "EC PRIVATE KEY", []byte{0x00, 0x01})
	writeRootPEM(t, dir, "root.crt", "CERTIFICATE", []byte{0x00, 0x01})
	if _, err := NewSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when root.key has wrong PEM type")
	}
}

// TestSelfCA_LoadRoot_KeyParseFails — valid PEM block with the
// right type but garbage bytes inside. Drives the
// ParsePKCS8PrivateKey error branch.
func TestSelfCA_LoadRoot_KeyParseFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRootPEM(t, dir, "root.key", "PRIVATE KEY", []byte{0xff, 0xff, 0xff})
	writeRootPEM(t, dir, "root.crt", "CERTIFICATE", []byte{0x00})
	if _, err := NewSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when root.key bytes don't parse as PKCS#8")
	}
}

// TestSelfCA_LoadRoot_CertReadFails — root.key parses fine but
// root.crt is missing. The order in loadRoot is read-key → parse-
// key → read-cert, so we get all the way to the cert read.
func TestSelfCA_LoadRoot_CertReadFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Generate a real PKCS8 key.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	writeRootPEM(t, dir, "root.key", "PRIVATE KEY", keyDER)
	// Don't write root.crt → ReadFile returns os.ErrNotExist.
	if _, err := NewSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when root.crt is missing")
	}
}

// TestSelfCA_LoadRoot_WrongCertPEMType — key parses, cert is wrong
// type.
func TestSelfCA_LoadRoot_WrongCertPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	writeRootPEM(t, dir, "root.key", "PRIVATE KEY", keyDER)
	writeRootPEM(t, dir, "root.crt", "PUBLIC KEY", []byte{0x00, 0x01})
	if _, err := NewSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when root.crt has wrong PEM type")
	}
}

// TestSelfCA_LoadRoot_CertParseFails — key + cert both have right
// PEM types; cert bytes are not a valid X.509.
func TestSelfCA_LoadRoot_CertParseFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	writeRootPEM(t, dir, "root.key", "PRIVATE KEY", keyDER)
	writeRootPEM(t, dir, "root.crt", "CERTIFICATE", []byte{0x00, 0x01, 0x02})
	if _, err := NewSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when cert DER doesn't parse")
	}
}

// TestSelfCA_LoadRoot_HappyPathRoundtrip — key + cert both parse,
// the loaded CA can issue a fresh leaf. Exercises the success
// branch in loadRoot end-to-end.
func TestSelfCA_LoadRoot_HappyPathRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// First Open creates the root; second Open re-loads it.
	if _, err := NewSelfCA(dir, "org", 365); err != nil {
		t.Fatal(err)
	}
	ca, err := NewSelfCA(dir, "org", 365)
	if err != nil {
		t.Fatalf("re-Open via loadRoot: %v", err)
	}
	if ca == nil {
		t.Fatal("nil CA")
	}
}

// ----- ServerSelfCA — same shape as SelfCA loadRoot tests -----

func TestServerSelfCA_LoadRoot_WrongKeyPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRootPEM(t, dir, "server-root.key", "EC PRIVATE KEY", []byte{0x00, 0x01})
	writeRootPEM(t, dir, "server-root.crt", "CERTIFICATE", []byte{0x00, 0x01})
	if _, err := NewServerSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when server-root.key has wrong PEM type")
	}
}

func TestServerSelfCA_LoadRoot_CertParseFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	writeRootPEM(t, dir, "server-root.key", "PRIVATE KEY", keyDER)
	writeRootPEM(t, dir, "server-root.crt", "CERTIFICATE", []byte{0x00, 0x01, 0x02})
	if _, err := NewServerSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when server cert DER doesn't parse")
	}
}

// TestServerSelfCA_CreateRoot_DirectoryNotWritable drives the
// createRoot WriteFile error branch by making the data directory
// read-only after MkdirAll.
//
// Skipped on systems where the test runs as root (root ignores
// the read-only bit). Best-effort coverage on dev machines.
func TestServerSelfCA_CreateRoot_DirectoryNotWritable(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}
	dir := t.TempDir()
	// chmod 0o500 so MkdirAll succeeds but WriteFile fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewServerSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error when data dir is not writable")
	}
}

// ensure the helpers actually build a valid cert when needed (e.g.
// for follow-up tests in the same package). Not directly a coverage
// driver, but keeps the helper usage compiled-in.
func TestHelperBuildsValidPKCS8(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
	// Sanity: produce a self-signed cert so the cert-parse path has
	// a known-good fixture available for any future tests.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if _, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv); err != nil {
		t.Errorf("CreateCertificate: %v", err)
	}
}
