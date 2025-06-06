package azurejwtvalidator

import (
	"net/http"
	"testing"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureJwtValidator_ExtractToken(t *testing.T) {
	t.Parallel()

	config := Config{
		KeysUrl:       "https://jwks.keys",
		Issuer:        "https://issuer.test",
		Audience:      "audience1,audience2",
		Roles:         []string{"Test.Role.1", "Test.Role.2"},
		MatchAllRoles: true,
	}
	l := logger.NewStdLog("warn")
	azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)

	t.Run("expect error if no authorization header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no authorization header")
	})

	t.Run("expect error if authorization header is not bearer auth scheme", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "something")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not bearer auth scheme")
	})

	t.Run("expect error if token isn't 3 parts", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token format")
	})

	t.Run("expect error if parts are not base64", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "Bearer not base64.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")

		req.Header.Del("Authorization")
		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.not base64.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")

		req.Header.Del("Authorization")
		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.not base64")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("expect error if jwt header can't be unmarshalled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "Bearer eyJ0ZXN0Ij0idGVzdCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("expect error if jwt payload can't be unmarshalled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0Ij0idGVzdCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		_, err = azureJwtValidator.ExtractToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("expect success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		jwt, err := azureJwtValidator.ExtractToken(req)
		assert.NoError(t, err)
		assert.Equal(t, "1234567890", jwt.Payload.Sub)
	})
}
