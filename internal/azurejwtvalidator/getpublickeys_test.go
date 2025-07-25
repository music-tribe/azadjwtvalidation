package azurejwtvalidator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
	"github.com/music-tribe/azadjwtvalidation/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAzureJwtValidator_verifyAndSetPublicKey(t *testing.T) {
	t.Parallel()

	pub := generatePublicKey(t)
	kid, err := jwtmodels.GenerateJwkKid(pub)
	require.NoError(t, err)

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
		actualPub, ok := azureJwtValidator.rsakeys.Get(kid)
		assert.True(t, ok, "expected public key to be set in map")
		assert.Equal(t, pub, actualPub, "expected public key to match the one set")
	})
}

func generatePublicKey(t *testing.T) *rsa.PublicKey {
	bitSize := 4096
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)
	return key.Public().(*rsa.PublicKey)
}

func TestAzureJwtValidator_GetPublicKeys(t *testing.T) {
	t.Parallel()

	config := Config{
		KeysUrl:       "https://jwks.keys",
		Issuer:        "https://issuer.test",
		Audience:      "audience1,audience2",
		Roles:         []string{"Test.Role.1", "Test.Role.2"},
		MatchAllRoles: true,
	}

	pub := generatePublicKey(t)
	kid, err := jwtmodels.GenerateJwkKid(pub)
	require.NoError(t, err)

	t.Run("expect error if verifyAndSetPublicKey fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)
		configWithInvalidPublicKey := config
		configWithInvalidPublicKey.PublicKey = "invalid public key"

		azureJwtValidator := NewAzureJwtValidator(configWithInvalidPublicKey, http.DefaultClient, l)
		err := azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key could not be decoded")
	})

	t.Run("expect error if we fail to get keys from url", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					nil,
					errors.New("failed to get")),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("failed to load public key from:https://jwks.keys")

		err := azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load public key from:")
	})

	t.Run("expect error if we fail to read response body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(errReader(0)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("failed to read response body from:https://jwks.keys")

		err := azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read response body from:")
	})

	t.Run("expect error if we fail to retrieve keys", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						Status:     "Forbidden",
						StatusCode: http.StatusForbidden,
						Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn(fmt.Sprintf("failed to retrieve keys. Response: %s, Body: %s", "Forbidden", "test"))

		err := azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve keys.")
	})

	t.Run("expect error if we fail to unmarshal public keys", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("failed to unmarshal public keys: invalid character 'e' in literal true (expecting 'r'). Response: , Body: test")

		err := azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal public keys")
	})

	t.Run("expect error if we there are no keys", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		noKeys := jwtmodels.JWKSet{
			Keys: []jwtmodels.JWK{},
		}
		noKeysBytes, err := json.Marshal(noKeys)
		require.NoError(t, err)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(noKeysBytes)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("failed to load public key. No keys found from:https://jwks.keys")

		err = azureJwtValidator.getPublicKeys()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load public key")
	})

	t.Run("expect error if we fail to parse E and key shouldn't be stored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		keys := jwtmodels.JWKSet{
			Keys: []jwtmodels.JWK{
				{
					Kid: kid,
					Kty: "RSA",
					Use: "sig",
					N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					E:   "invalid base64!",
				},
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(keysBytes)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("Error parsing key E:illegal base64 data at input byte 7")

		err = azureJwtValidator.getPublicKeys()
		// No error returned because we loop over many keys but we need to ensure we don't store the dodgy key in our map
		assert.NoError(t, err)
		assert.True(t, azureJwtValidator.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})

	t.Run("expect error if we fail to decode N and key shouldn't be stored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		keys := jwtmodels.JWKSet{
			Keys: []jwtmodels.JWK{
				{
					Kid: kid,
					Kty: "RSA",
					Use: "sig",
					N:   "not a number",
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(keysBytes)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")
		l.EXPECT().Warn("Error decoding key N:illegal base64 data at input byte 3")

		err = azureJwtValidator.getPublicKeys()
		// No error returned because we loop over many keys but we need to ensure we don't store the dodgy key in our map
		assert.NoError(t, err)
		assert.True(t, azureJwtValidator.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})

	t.Run("expect success and key stored in map with thumbprint kid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		keys := jwtmodels.JWKSet{
			Keys: []jwtmodels.JWK{
				{
					Kid: kid,
					Kty: "RSA",
					Use: "sig",
					N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(keysBytes)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")

		err = azureJwtValidator.getPublicKeys()
		assert.NoError(t, err)
		assert.True(t, azureJwtValidator.rsakeys.Len() > 0, "expected public keys to be loaded")
		actualPub, ok := azureJwtValidator.rsakeys.Get(kid)
		assert.True(t, ok, "expected public key to be set in map")
		assert.Equal(t, pub, actualPub, "expected public key to match the one set")
	})

	t.Run("expect success and multiple keys stored in map with thumbprint kid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		l := logger.NewMockLogger(ctrl)

		pub2 := generatePublicKey(t)
		kid2, err := jwtmodels.GenerateJwkKid(pub2)
		require.NoError(t, err)

		keys := jwtmodels.JWKSet{
			Keys: []jwtmodels.JWK{
				{
					Kid: kid,
					Kty: "RSA",
					Use: "sig",
					N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
				{
					Kid: kid2,
					Kty: "RSA",
					Use: "sig",
					N:   base64.RawURLEncoding.EncodeToString(pub2.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub2.E)).Bytes()),
				},
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		azureJwtValidator := NewAzureJwtValidator(config,
			&http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(keysBytes)),
					},
					nil),
			},
			l)

		l.EXPECT().Debug("Fetching public keys from: https://jwks.keys")

		err = azureJwtValidator.getPublicKeys()
		assert.NoError(t, err)
		assert.True(t, azureJwtValidator.rsakeys.Len() > 0, "expected public keys to be loaded")

		actualPub, ok := azureJwtValidator.rsakeys.Get(kid)
		assert.True(t, ok, "expected public key to be set in map")
		assert.Equal(t, pub, actualPub, "expected public key to match the one set")

		actualPub2, ok := azureJwtValidator.rsakeys.Get(kid2)
		assert.True(t, ok, "expected public key to be set in map")
		assert.Equal(t, pub2, actualPub2, "expected public key to match the one set")

		assert.True(t, azureJwtValidator.rsakeys.Len() == 2)
	})
}

func TestAzureJwtValidator_getPublicKeysWithBackoffRetry(t *testing.T) {
	t.Run("expect to fail and retry a few times", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ml := logger.NewMockLogger(ctrl)

		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                      "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience:                     "test-audience",
				Issuer:                       "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:                        []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes:       1,
				UpdateKeysWithBackoffRetries: 3,
			},
			client: &http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusServiceUnavailable,
					},
					nil),
			},
			logger:  ml,
			rsakeys: NewPublicKeys(),
		}

		ml.EXPECT().Debug("Fetching public keys from: https://login.microsoftonline.com/common/discovery/v2.0/keys").Times(4)
		ml.EXPECT().Warn("failed to retrieve keys. Response: , Body: ").Times(4)

		err := azjwt.getPublicKeysWithBackoffRetry(context.TODO())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve keys. Response: , Body: ")
	})

	t.Run("expect to stop retrying when context is done", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ml := logger.NewMockLogger(ctrl)

		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                      "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience:                     "test-audience",
				Issuer:                       "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:                        []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes:       1,
				UpdateKeysWithBackoffRetries: 100,
			},
			client: &http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusServiceUnavailable,
					},
					nil),
			},
			logger:  ml,
			rsakeys: NewPublicKeys(),
		}

		ml.EXPECT().Debug("Fetching public keys from: https://login.microsoftonline.com/common/discovery/v2.0/keys").Times(1)

		// Expect to not even get to retry because the context will be done immediately
		ml.EXPECT().Warn("failed to retrieve keys. Response: , Body: ").Times(1)

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()
		err := azjwt.getPublicKeysWithBackoffRetry(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve keys. Response: , Body: ")
	})
}

func TestAzureJwtValidator_GetPublicKeysWithOptionalBackoffRetry(t *testing.T) {
	t.Run("expect to retry if we get a transient error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ml := logger.NewMockLogger(ctrl)
		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                      "https://jwks.keys",
				Audience:                     "test-audience",
				Issuer:                       "https://issuer.test",
				Roles:                        []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes:       1,
				UpdateKeysWithBackoffRetries: 3,
			},
			client: &http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusServiceUnavailable,
					},
					nil),
			},
			logger:  ml,
			rsakeys: NewPublicKeys(),
		}

		ml.EXPECT().Debug("Fetching public keys from: https://jwks.keys").Times(4)
		ml.EXPECT().Warn("failed to retrieve keys. Response: , Body: ").Times(4)
		ml.EXPECT().Warn("failed to get public keys after 3 retries: failed to retrieve keys. Response: , Body: ").Times(1)

		azjwt.GetPublicKeysWithOptionalBackoffRetry(context.TODO())
		assert.True(t, azjwt.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})

	t.Run("expect to not retry if we don't set backoff retries", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ml := logger.NewMockLogger(ctrl)
		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                "https://jwks.keys",
				Audience:               "test-audience",
				Issuer:                 "https://issuer.test",
				Roles:                  []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes: 1,
			},
			client: &http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusServiceUnavailable,
					},
					nil),
			},
			logger:  ml,
			rsakeys: NewPublicKeys(),
		}

		ml.EXPECT().Debug("Fetching public keys from: https://jwks.keys").Times(1)
		ml.EXPECT().Warn("failed to retrieve keys. Response: , Body: ").Times(1)
		ml.EXPECT().Warn("failed to get public keys after 0 retries: failed to retrieve keys. Response: , Body: ").Times(1)

		azjwt.GetPublicKeysWithOptionalBackoffRetry(context.TODO())
		assert.True(t, azjwt.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})
}
