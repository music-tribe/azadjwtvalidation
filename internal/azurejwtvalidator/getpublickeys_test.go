package azurejwtvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureJwtValidator_verifyAndSetPublicKey(t *testing.T) {
	t.Parallel()

	pub := generatePublicKey(t)

	config := Config{
		KeysUrl:       "https://jwks.keys",
		Issuer:        "https://issuer.test",
		Audience:      "audience1,audience2",
		Roles:         []string{"Test.Role.1", "Test.Role.2"},
		MatchAllRoles: true,
	}
	l := logger.NewStdLog("warn")

	t.Run("expect error if public key is invalid", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azureJwtValidator.verifyAndSetPublicKey("invalid public key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key could not be decoded")
	})

	t.Run("expect error if public key is not rsa", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)
		var pubPEMData = []byte(`
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----
and some more`)
		err := azureJwtValidator.verifyAndSetPublicKey(string(pubPEMData))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key format invalid")
	})

	t.Run("expect error if public key can not be parsed as RSA", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)

		// Encode public key to PKCS#1 ASN.1 PEM. we want PKIX
		pubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(pub),
			},
		)
		err := azureJwtValidator.verifyAndSetPublicKey(string(pubPEM))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse RSA public key")
	})

	t.Run("expect error if public key can not be parsed as RSA", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)

		// Encode public key to PKCS#1 ASN.1 PEM. we want PKIX
		pubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(pub),
			},
		)
		err := azureJwtValidator.verifyAndSetPublicKey(string(pubPEM))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse RSA public key")
	})

	// TODO: how to test "unable to convert RSA public key"

	t.Run("expect no error if public key is valid", func(t *testing.T) {
		azureJwtValidator := NewAzureJwtValidator(config, http.DefaultClient, l)
		// Encode public key PKIX
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
		pubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pubBytes,
			},
		)
		err = azureJwtValidator.verifyAndSetPublicKey(string(pubPEM))
		assert.NoError(t, err)
		assert.NotNil(t, azureJwtValidator.rsakeys)
		assert.Equal(t, pub, azureJwtValidator.rsakeys["config_rsa"])
	})
}

func generatePublicKey(t *testing.T) *rsa.PublicKey {
	bitSize := 4096
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)
	return key.Public().(*rsa.PublicKey)
}
