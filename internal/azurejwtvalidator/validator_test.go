package azurejwtvalidator

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAzureJwtValidator(t *testing.T) {
	t.Run("expect non nil rsakeys", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(http.DefaultClient)
		assert.NotNil(t, azureJwtValidator.rsakeys)
	})

	t.Run("expect our client to be set", func(t *testing.T) {
		client := http.DefaultClient
		azureJwtValidator := NewAzureJwtValidator(client)
		assert.Equal(t, client, azureJwtValidator.client)
	})
}
