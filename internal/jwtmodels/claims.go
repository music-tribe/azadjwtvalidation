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
	Scp   string      `json:"scp"`   // az b2c uses scp (scope) for roles: https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#claims
	Roles []string    `json:"roles"` // roles kept here for backwards compatibility, but scp is preferred
}

func (claims *Claims) isValidForRole(allowedRole string, l logger.Logger) bool {
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

func (claims *Claims) validateRoles(allowedRoles []string, matchAllRoles bool, l logger.Logger) error {
	if claims.Roles != nil {
		if len(allowedRoles) > 0 {
			var allRolesValid = true
			if !matchAllRoles {
				allRolesValid = false
			}

			for _, role := range allowedRoles {
				roleValid := claims.isValidForRole(role, l)
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

func (claims *Claims) scopeToRoles() {
	// Don't overwrite any existing roles
	if len(claims.Roles) > 0 {
		return
	}

	// Create roles from scp
	if claims.Scp != "" {
		// Split the scp string by space
		scpRoles := strings.Split(claims.Scp, " ")
		// Remove empty roles
		for _, role := range scpRoles {
			if role != "" {
				claims.Roles = append(claims.Roles, role)
			}
		}
	}
}

func (claims *Claims) Validate(audience, issuer string, allowedRoles []string, matchAllRoles bool, l logger.Logger) error {
	claims.scopeToRoles()

	// We need to guarantee prior that audience and issuer are not blank
	if !strings.Contains(audience, claims.Aud) {
		return errors.New("token audience is wrong")
	}

	if claims.Iss != issuer {
		return errors.New("wrong issuer")
	}

	err := claims.validateRoles(allowedRoles, matchAllRoles, l)
	if err != nil {
		return err
	}

	return nil
}
