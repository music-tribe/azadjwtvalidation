package jwtmodels

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKThumbprintInput holds the canonical JWK fields for thumbprint
// https://www.rfc-editor.org/rfc/rfc7638.html#section-3.1
// We don't use JWK because of the extra fields resulting in incorrect json bytes
type JWKThumbprintInput struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

func GenerateJwkKid(pubKey *rsa.PublicKey) (string, error) {
	// Convert exponent and modulus to base64url
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	nBytes := pubKey.N.Bytes()

	jwk := JWKThumbprintInput{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	// Canonical JSON encoding (sorted keys, no extra whitespace)
	jsonBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(jsonBytes)

	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
