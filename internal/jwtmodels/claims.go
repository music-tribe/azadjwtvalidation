package jwtmodels

import (
	"encoding/json"
	"log"
)

type Claims struct {
	Iat   json.Number `json:"iat"`
	Exp   json.Number `json:"exp"`
	Iss   string      `json:"iss"`
	Aud   string      `json:"aud"`
	Sub   string      `json:"sub"`
	Roles []string    `json:"roles"`
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
