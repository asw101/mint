package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func pemBytes(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestParsePEMSignerAcceptsPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded := pemBytes(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))

	signer, err := ParsePEMSigner(encoded)
	if err != nil {
		t.Fatalf("ParsePEMSigner: %v", err)
	}
	if !signer.Public().Equal(&key.PublicKey) {
		t.Error("parsed key does not match the original")
	}
}

func TestParsePEMSignerAcceptsPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	signer, err := ParsePEMSigner(pemBytes(t, "PRIVATE KEY", der))
	if err != nil {
		t.Fatalf("ParsePEMSigner: %v", err)
	}
	if !signer.Public().Equal(&key.PublicKey) {
		t.Error("parsed key does not match the original")
	}
}

func TestParsePEMSignerSkipsLeadingNonKeyBlocks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	document := append(
		pemBytes(t, "CERTIFICATE", []byte("not a key")),
		pemBytes(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))...,
	)

	if _, err := ParsePEMSigner(document); err != nil {
		t.Fatalf("ParsePEMSigner: %v", err)
	}
}

func TestParsePEMSignerRejectsNonRSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	_, err = ParsePEMSigner(pemBytes(t, "PRIVATE KEY", der))
	if err == nil || !strings.Contains(err.Error(), "require RSA") {
		t.Fatalf("got %v, want an RSA-required error", err)
	}
}

func TestParsePEMSignerRejectsEncryptedKey(t *testing.T) {
	encrypted := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123"},
		Bytes:   []byte("ciphertext"),
	})

	_, err := ParsePEMSigner(encrypted)
	if err == nil || !strings.Contains(err.Error(), "passphrase-encrypted") {
		t.Fatalf("got %v, want a passphrase error", err)
	}
}

func TestParsePEMSignerRejectsGarbage(t *testing.T) {
	if _, err := ParsePEMSigner([]byte("definitely not PEM")); err == nil {
		t.Error("want error for non-PEM input")
	}
}

func TestPEMSignerSignIsVerifiable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := &PEMSigner{key: key}

	signature, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signature) != key.Size() {
		t.Errorf("got %d byte signature, want %d", len(signature), key.Size())
	}
}
