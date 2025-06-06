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

func (claims *Claims) IsValidForRole(allowedRole string, l logger.Logger) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == allowedRole {
			l.Debug(fmt.Sprintf("Match: parsedRole: %s, allowedRole: %s", parsedRole, allowedRole))
			return true
		} else {
			l.Debug(fmt.Sprintf("No match: parsedRole: %s, allowedRole: %s", parsedRole, allowedRole))
		}
	}

	return false
}

func (claims *Claims) ValidateRoles(allowedRoles []string, matchAllRoles bool, l logger.Logger) error {
	if claims.Roles != nil {
		if len(allowedRoles) > 0 {
			var allRolesValid = true
			if !matchAllRoles {
				allRolesValid = false
			}

			for _, role := range allowedRoles {
				roleValid := claims.IsValidForRole(role, l)
				if matchAllRoles && !roleValid {
					allRolesValid = false
					break
				}
				if !matchAllRoles && roleValid {
					allRolesValid = true
					break
				}
			}

			if !allRolesValid {
				l.Warn("missing correct role, found: " + strings.Join(claims.Roles, ",") + ", expected: " + strings.Join(allowedRoles, ","))
				return errors.New("missing correct role")
			}
		}
	} else if len(allowedRoles) > 0 {
		return errors.New("missing correct role")
	}
	return nil
}
