package azurejwtvalidator

import (
	"net/http"
	"testing"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
	"github.com/stretchr/testify/assert"
)

func TestNewAzureJwtValidator(t *testing.T) {
	config := Config{
		KeysUrl:       "https://jwks.keys",
		Issuer:        "https://issuer.test",
		Audience:      "audience1,audience2",
		Roles:         []string{"Test.Role.1", "Test.Role.2"},
		MatchAllRoles: true,
	}
	logger := logger.NewStdLog("warn")

	t.Run("expect non nil rsakeys", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, logger)
		assert.NotNil(t, azureJwtValidator.rsakeys)
	})

	t.Run("expect our client to be set", func(t *testing.T) {
		client := http.DefaultClient
		azureJwtValidator := NewAzureJwtValidator(config, client, logger)
		assert.Equal(t, client, azureJwtValidator.client)
	})

	t.Run("expect panic if config is invalid", func(t *testing.T) {
		invalidConfig := Config{
			KeysUrl: "https://jwks.keys",
		}
		assert.Panics(t, func() {
			NewAzureJwtValidator(invalidConfig, http.DefaultClient, logger)
		})
	})
}
