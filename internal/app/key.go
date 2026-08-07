// Package app mints GitHub App credentials: the signed JWT that identifies
// the App, and the short-lived installation access tokens derived from it.
package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Signer produces RSASSA-PKCS1-v1_5 signatures over SHA-256 digests — the
// RS256 algorithm GitHub requires for App JWTs.
//
// PEMSigner is the only implementation today. The interface exists so a
// signer backed by SSH_AUTH_SOCK can be added without touching the JWT or
// API layers, letting the App key stay in an agent rather than on disk.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// PEMSigner signs with an RSA private key held in memory, read from the PEM
// file GitHub issues when an App key is generated.
type PEMSigner struct {
	key *rsa.PrivateKey
}

// LoadPEMSigner reads and parses a private key PEM file.
func LoadPEMSigner(path string) (*PEMSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	signer, err := ParsePEMSigner(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return signer, nil
}

// ParsePEMSigner parses the first private key block in a PEM document.
// GitHub issues PKCS#1 ("RSA PRIVATE KEY"); PKCS#8 is accepted too, since
// converting the key with OpenSSL is a common intermediate step.
func ParsePEMSigner(data []byte) (*PEMSigner, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no PEM private key block found")
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		if _, encrypted := block.Headers["DEK-Info"]; encrypted {
			return nil, errors.New("private key is passphrase-encrypted; decrypt it first with 'openssl rsa'")
		}
		key, err := parseRSAPrivateKey(block)
		if err != nil {
			return nil, err
		}
		return &PEMSigner{key: key}, nil
	}
}

func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s block: %w", block.Type, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T; GitHub App JWTs require RSA", parsed)
	}
	return key, nil
}

// Sign implements Signer.
func (s *PEMSigner) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
}

// Public returns the verifying half of the key.
func (s *PEMSigner) Public() *rsa.PublicKey { return &s.key.PublicKey }
