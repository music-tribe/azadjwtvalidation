package azurejwtvalidator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_validate(t *testing.T) {
	t.Run("expect error if Issuer isn't present", func(t *testing.T) {
		config := Config{
			KeysUrl: "https://jwks.keys",
		}
		err := config.validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error:Field validation for 'Issuer' failed on the 'required' tag")
	})
	t.Run("expect error if Audience isn't present", func(t *testing.T) {
		config := Config{
			KeysUrl: "https://jwks.keys",
			Issuer:  "https://issuer.test",
		}
		err := config.validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error:Field validation for 'Audience' failed on the 'required' tag")
	})
	t.Run("expect Issuer to be a http url string", func(t *testing.T) {
		config := Config{
			KeysUrl: "https://jwks.keys",
			Issuer:  "not http url string",
		}
		err := config.validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error:Field validation for 'Issuer' failed on the 'http_url' tag")
	})
	t.Run("expect PublicKey to be optional if KeysUrl is present", func(t *testing.T) {
		config := Config{
			KeysUrl:  "https://jwks.keys",
			Issuer:   "https://issuer.test",
			Audience: "audience1",
		}
		err := config.validate()
		assert.NoError(t, err)
	})
	t.Run("expect KeysUrl to be optional if PublicKey is present", func(t *testing.T) {
		config := Config{
			PublicKey: "some public-key",
			Issuer:    "https://issuer.test",
			Audience:  "audience1",
		}
		err := config.validate()
		assert.NoError(t, err)
	})
}
