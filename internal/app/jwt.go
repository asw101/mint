package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// jwtLifetime is how long a minted JWT stays valid. GitHub rejects
	// anything over 10 minutes. iat is backdated by clockSkew below, so the
	// two together must stay under that ceiling: 8 + 1 leaves a minute of
	// margin rather than landing exactly on the limit.
	jwtLifetime = 8 * time.Minute

	// clockSkew backdates iat so a slightly fast local clock does not mint a
	// token GitHub reads as issued in the future.
	clockSkew = 60 * time.Second
)

// MintJWT returns an RS256 JWT identifying the App. Every /app endpoint takes
// this in place of a token; installation tokens are then minted with it.
//
// appID accepts either the numeric App ID or the App's client ID.
func MintJWT(signer Signer, appID string, now time.Time) (string, error) {
	if signer == nil {
		return "", errors.New("no signer configured")
	}
	if strings.TrimSpace(appID) == "" {
		return "", errors.New("no app ID configured (set --app-id or GH_APP_ID)")
	}

	header, err := encodeSegment(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := encodeSegment(map[string]any{
		"iat": now.Add(-clockSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}

	signingInput := header + "." + claims
	signature, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeSegment(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode JWT segment: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}
