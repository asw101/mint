package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *PEMSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &PEMSigner{key: key}
}

func TestMintJWTSignsVerifiableClaims(t *testing.T) {
	signer := testKey(t)
	now := time.Unix(1_700_000_000, 0)

	token, err := MintJWT(signer, "123456", now)
	if err != nil {
		t.Fatalf("MintJWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d JWT segments, want 3", len(parts))
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(signer.Public(), crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	decodeSegment(t, parts[0], &header)
	if header.Alg != "RS256" || header.Typ != "JWT" {
		t.Fatalf("got header %+v, want RS256/JWT", header)
	}

	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	decodeSegment(t, parts[1], &claims)
	if claims.Iss != "123456" {
		t.Errorf("got iss %q, want 123456", claims.Iss)
	}
	if want := now.Add(-clockSkew).Unix(); claims.Iat != want {
		t.Errorf("got iat %d, want %d (backdated by clock skew)", claims.Iat, want)
	}
	if want := now.Add(jwtLifetime).Unix(); claims.Exp != want {
		t.Errorf("got exp %d, want %d", claims.Exp, want)
	}
	// GitHub rejects a window wider than 10 minutes, measured from iat.
	if window := time.Duration(claims.Exp-claims.Iat) * time.Second; window > 10*time.Minute {
		t.Errorf("validity window %s exceeds GitHub's 10 minute maximum", window)
	}
}

func TestMintJWTRejectsMissingInputs(t *testing.T) {
	if _, err := MintJWT(nil, "123456", time.Now()); err == nil {
		t.Error("want error for nil signer")
	}
	if _, err := MintJWT(testKey(t), "  ", time.Now()); err == nil {
		t.Error("want error for blank app ID")
	}
}

type failingSigner struct{}

func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("agent refused") }

func TestMintJWTPropagatesSignerError(t *testing.T) {
	_, err := MintJWT(failingSigner{}, "123456", time.Now())
	if err == nil || !strings.Contains(err.Error(), "agent refused") {
		t.Fatalf("got %v, want the signer's error", err)
	}
}

func decodeSegment(t *testing.T, segment string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}
