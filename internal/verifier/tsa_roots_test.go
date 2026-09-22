package verifier

import (
	"encoding/pem"
	"testing"
)

func TestParseTSARootsPEM(t *testing.T) {
	if _, err := ParseTSARootsPEM(nil); err == nil {
		t.Fatal("empty PEM was accepted")
	}
	if _, err := ParseTSARootsPEM([]byte("not a certificate")); err == nil {
		t.Fatal("a PEM with no certificates was accepted")
	}
	der, _, _, _ := testTSA(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool, err := ParseTSARootsPEM(pemBytes)
	if err != nil {
		t.Fatalf("a valid TSA certificate was refused: %v", err)
	}
	if pool == nil {
		t.Fatal("ParseTSARootsPEM returned a nil pool for a certificate it accepted")
	}
}
