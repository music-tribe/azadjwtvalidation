package jwtmodels

import (
	"encoding/json"
	"log"
)

type AzureJwt struct {
	Header     AzureJwtHeader
	Payload    Claims
	Signature  []byte
	RawToken   []byte
	RawPayload []byte
}

type AzureJwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type Claims struct {
	Iat   json.Number `json:"iat"`
	Exp   json.Number `json:"exp"`
	Iss   string      `json:"iss"`
	Aud   string      `json:"aud"`
	Sub   string      `json:"sub"`
	Roles []string    `json:"roles"`
}

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

func (claims *Claims) IsValidForRole(configRole string, debugLogger *log.Logger) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == configRole {
			debugLogger.Println("Match:", parsedRole, configRole)
			return true
		} else {
			debugLogger.Println("No match:", parsedRole, configRole)
		}
	}

	return false
}
