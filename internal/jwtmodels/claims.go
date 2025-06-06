package jwtmodels

import (
	"encoding/json"
	"fmt"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
)

type Claims struct {
	Iat   json.Number `json:"iat"`
	Exp   json.Number `json:"exp"`
	Iss   string      `json:"iss"`
	Aud   string      `json:"aud"`
	Sub   string      `json:"sub"`
	Roles []string    `json:"roles"`
}

func (claims *Claims) IsValidForRole(configRole string, l logger.Logger) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == configRole {
			l.Debug(fmt.Sprintf("Match: parsedRole: %s, configRole: %s", parsedRole, configRole))
			return true
		} else {
			l.Debug(fmt.Sprintf("No match: parsedRole: %s, configRole: %s", parsedRole, configRole))
		}
	}

	return false
}
