package jwtmodels

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

func (claims *Claims) ValidateRoles(configRoles []string, configMatchAllRoles bool, l logger.Logger) error {
	if claims.Roles != nil {
		if len(configRoles) > 0 {
			var allRolesValid = true
			if !configMatchAllRoles {
				allRolesValid = false
			}

			for _, role := range configRoles {
				roleValid := claims.IsValidForRole(role, l)
				if configMatchAllRoles && !roleValid {
					allRolesValid = false
					break
				}
				if !configMatchAllRoles && roleValid {
					allRolesValid = true
					break
				}
			}

			if !allRolesValid {
				l.Warn("missing correct role, found: " + strings.Join(claims.Roles, ",") + ", expected: " + strings.Join(configRoles, ","))
				return errors.New("missing correct role")
			}
		}
	} else if len(configRoles) > 0 {
		return errors.New("missing correct role")
	}
	return nil
}
