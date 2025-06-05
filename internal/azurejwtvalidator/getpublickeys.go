package azurejwtvalidator

import (
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

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
)

func (azjwt *AzureJwtValidator) GetPublicKeys(config *Config) error {
	azjwt.verifyAndSetPublicKey(config.PublicKey)

	if strings.TrimSpace(config.KeysUrl) != "" {
		var body jwtmodels.JWKSet
		resp, err := azjwt.client.Get(config.KeysUrl)

		if err != nil {
			e := fmt.Errorf("failed to load public key from:%v", config.KeysUrl)
			azjwt.logger.Warn(e.Error())
			return e
		}
		defer resp.Body.Close()
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			e := fmt.Errorf("failed to read response body from:%v", config.KeysUrl)
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
			e := fmt.Errorf("failed to load public key. No keys found from:%v", config.KeysUrl)
			azjwt.logger.Warn(e.Error())
			return e
		}
		for _, key := range keys {
			kid := key.Kid
			e := key.E
			rsakey := new(rsa.PublicKey)
			// FIXME: no error checking here
			number, _ := base64.RawURLEncoding.DecodeString(key.N)
			rsakey.N = new(big.Int).SetBytes(number)

			b, err := base64.RawURLEncoding.DecodeString(e)
			if err != nil {
				azjwt.logger.Warn(fmt.Sprintf("Error parsing key E:%v", err))
				continue
			}

			rsakey.E = int(new(big.Int).SetBytes(b).Uint64())
			azjwt.rsakeys[kid] = rsakey
		}
	}

	return nil
}

func (azjwt *AzureJwtValidator) verifyAndSetPublicKey(publicKey string) error {
	// FIXME: we are clearing the public keys map, potentially asynchrously & resulting in no public keys when validating tokens
	// This could explain our random 403s
	azjwt.rsakeys = make(map[string]*rsa.PublicKey)

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
		azjwt.rsakeys["config_rsa"] = pubKey
	}

	return nil
}
