package azurejwtvalidator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/cenkalti/backoff/v5"
	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
)

// Get public keys. Will retry if Config.UpdateKeysWithBackoffRetries is set.
// If Config.UpdateKeysWithBackoffRetries is set to 0, it will not retry and will return an error if the keys cannot be retrieved.
// If Config.UpdateKeysWithBackoffRetries is set to a positive number, it will retry that many times with exponential backoff.
func (azjwt *AzureJwtValidator) GetPublicKeysWithOptionalBackoffRetry(ctx context.Context) error {
	withBackoffOperation := func() error {
		return azjwt.getPublicKeysWithBackoffRetry(ctx)
	}
	withoutBackoffOperation := func() error {
		return azjwt.GetPublicKeys()
	}

	var operation func() error
	if azjwt.config.UpdateKeysWithBackoffRetries > 0 {
		operation = withBackoffOperation
	} else {
		operation = withoutBackoffOperation
	}

	err := operation()
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("failed to get public keys after %d retries: %v", azjwt.config.UpdateKeysWithBackoffRetries, err))
	}
	return err
}

// FIXME: this doesn't need to be public
func (azjwt *AzureJwtValidator) GetPublicKeys() error {
	err := azjwt.verifyAndSetPublicKey(azjwt.config.PublicKey)
	if err != nil {
		return err
	}

	if strings.TrimSpace(azjwt.config.KeysUrl) != "" {
		var body jwtmodels.JWKSet
		resp, err := azjwt.client.Get(azjwt.config.KeysUrl)

		if err != nil {
			e := fmt.Errorf("failed to load public key from:%v", azjwt.config.KeysUrl)
			azjwt.logger.Warn(e.Error())
			return e
		}
		defer resp.Body.Close()
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			e := fmt.Errorf("failed to read response body from:%v", azjwt.config.KeysUrl)
			azjwt.logger.Warn(e.Error())
			return e
		}

		if resp.StatusCode != http.StatusOK {
			e := fmt.Errorf("failed to retrieve keys. Response: %s, Body: %s", resp.Status, bytes)
			azjwt.logger.Warn(e.Error())
			return e
		}

		err = json.Unmarshal(bytes, &body)
		if err != nil {
			e := fmt.Errorf("failed to unmarshal public keys: %v. Response: %s, Body: %s", err, resp.Status, bytes)
			azjwt.logger.Warn(e.Error())
			return e
		}

		keys := body.Keys

		if len(keys) == 0 {
			e := fmt.Errorf("failed to load public key. No keys found from:%v", azjwt.config.KeysUrl)
			azjwt.logger.Warn(e.Error())
			return e
		}
		rsakeys := make(map[string]*rsa.PublicKey)
		for _, key := range keys {
			kid := key.Kid
			e := key.E
			rsakey := new(rsa.PublicKey)
			number, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				azjwt.logger.Warn(fmt.Sprintf("Error decoding key N:%v", err))
				continue
			}
			rsakey.N = new(big.Int).SetBytes(number)

			b, err := base64.RawURLEncoding.DecodeString(e)
			if err != nil {
				azjwt.logger.Warn(fmt.Sprintf("Error parsing key E:%v", err))
				continue
			}

			rsakey.E = int(new(big.Int).SetBytes(b).Uint64())
			rsakeys[kid] = rsakey
		}
		if len(rsakeys) != 0 {
			azjwt.rsakeys.Write(rsakeys)
		}
	}

	return nil
}

func (azjwt *AzureJwtValidator) verifyAndSetPublicKey(publicKey string) error {
	// publicKey is optional
	if strings.TrimSpace(publicKey) == "" {
		return nil
	}

	pubPem, _ := pem.Decode([]byte(publicKey))
	if pubPem == nil {
		return fmt.Errorf("public key could not be decoded")
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		return fmt.Errorf("public key format invalid")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return fmt.Errorf("unable to parse RSA public key")
	}

	if pubKey, ok := parsedKey.(*rsa.PublicKey); !ok {
		return fmt.Errorf("unable to convert RSA public key")
	} else {
		kid, err := jwtmodels.GenerateJwkKid(pubKey)
		if err != nil {
			return fmt.Errorf("failed to generate JWK kid: %v", err)
		}
		azjwt.rsakeys.Set(kid, pubKey)
	}

	return nil
}

func (azjwt *AzureJwtValidator) getPublicKeysWithBackoffRetry(ctx context.Context) error {
	operation := func() (string, error) {
		return "", azjwt.GetPublicKeys()
	}
	_, err := backoff.Retry(ctx, operation, backoff.WithMaxTries(azjwt.config.UpdateKeysWithBackoffRetries), backoff.WithBackOff(backoff.NewExponentialBackOff()))
	if err != nil {
		return err
	}
	return nil
}
