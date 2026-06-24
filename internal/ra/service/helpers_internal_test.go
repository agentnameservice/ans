package service

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestSerialFromCertPEM_Errors(t *testing.T) {
	if _, err := serialFromCertPEM(""); err == nil {
		t.Error("want error for empty PEM")
	}
	if _, err := serialFromCertPEM("not pem at all"); err == nil {
		t.Error("want error for non-PEM input")
	}
	wrongType := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))
	if _, err := serialFromCertPEM(wrongType); err == nil {
		t.Error("want error for non-CERTIFICATE block")
	}
	badDER := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0xff}}))
	if _, err := serialFromCertPEM(badDER); err == nil || !strings.Contains(err.Error(), "parse certificate") {
		t.Errorf("want parse error for garbage DER, got %v", err)
	}
}
