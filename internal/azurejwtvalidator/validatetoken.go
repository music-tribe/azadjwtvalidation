package azurejwtvalidator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
)

// ValidateToken checks we have a public key for this token's kid, verifies the signature, and checks the token's claims.
func (azjwt *AzureJwtValidator) ValidateToken(token *jwtmodels.AzureJwt) error {
	hash := sha256.Sum256(token.RawToken)

	pub, ok := azjwt.rsakeys.Get(token.Header.Kid)
	if !ok || pub == nil {
		return errors.New("invalid public key")
	}

	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], token.Signature)
	if err != nil {
		return err
	}

	if err := azjwt.verifyToken(token); err != nil {
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
