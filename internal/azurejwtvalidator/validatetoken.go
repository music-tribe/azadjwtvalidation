package azurejwtvalidator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
)

func (azjwt *AzureJwtValidator) ValidateToken(token *jwtmodels.AzureJwt) error {
	hash := sha256.Sum256(token.RawToken)

	if _, ok := azjwt.rsakeys[token.Header.Kid]; !ok {
		return errors.New("invalid public key")
	}

	err := rsa.VerifyPKCS1v15(azjwt.rsakeys[token.Header.Kid], crypto.SHA256, hash[:], token.Signature)
	if err != nil {
		return err
	}

	if err := azjwt.verifyToken(token); err != nil {
		return err
	}

	// FIXME: haven't we already go the Claims in the Payload?
	var claims jwtmodels.Claims
	if err := json.Unmarshal(token.RawPayload, &claims); err != nil {
		return err
	}

	return nil
}

func (azjwt *AzureJwtValidator) verifyToken(jwtToken *jwtmodels.AzureJwt) error {
	tokenExpiration, err := jwtToken.Payload.Exp.Int64()
	if err != nil {
		return err
	}

	if tokenExpiration < time.Now().Unix() {
		azjwt.logger.Warn(fmt.Sprintf("Token has expired: %s", time.Unix(tokenExpiration, 0).UTC().Format(time.RFC3339)))
		return errors.New("token is expired")
	}

	err = jwtToken.Payload.Validate(azjwt.config.Audience, azjwt.config.Issuer, azjwt.config.Roles, azjwt.config.MatchAllRoles, azjwt.logger)
	if err != nil {
		return err
	}

	return nil
}
