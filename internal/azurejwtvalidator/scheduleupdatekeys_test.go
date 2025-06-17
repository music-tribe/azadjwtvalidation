package azurejwtvalidator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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

func TestAzureJwtValidator_ScheduleUpdateKeys(t *testing.T) {
	t.Parallel()

	t.Run("expect to return if context is done", func(t *testing.T) {
		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience:               "test-audience",
				Issuer:                 "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:                  []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes: 1,
			},
			client:  http.DefaultClient,
			logger:  logger.NewStdLog("warn"),
			rsakeys: NewPublicKeys(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(time.Duration(azjwt.config.UpdateKeysEveryMinutes) * time.Minute)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
	})

	t.Run("expect to get public keys", func(t *testing.T) {
		pub := generatePublicKey(t)
		kid, err := jwtmodels.GenerateJwkKid(pub)
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
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:                "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience:               "test-audience",
				Issuer:                 "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:                  []string{"Test.Role.1", "Test.Role.2"},
				UpdateKeysEveryMinutes: 1,
			},
			client: &http.Client{
				Transport: newStubRoundTripper(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(keysBytes)),
					},
					nil),
			},
			logger:  logger.NewStdLog("warn"),
			rsakeys: NewPublicKeys(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
		assert.True(t, azjwt.rsakeys.Len() > 0, "expected public keys to be loaded")
	})

	t.Run("expect to get warning log if we error getting public keys", func(t *testing.T) {
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

		ml.EXPECT().Warn("failed to retrieve keys. Response: , Body: ").AnyTimes()
		ml.EXPECT().Warn("failed to get public keys after 0 retries: failed to retrieve keys. Response: , Body: ").AnyTimes()
		ml.EXPECT().Warn("ScheduleUpdateKeys: failed to retrieve keys. Response: , Body: ").AnyTimes()

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
		assert.True(t, azjwt.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})

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
				UpdateKeysWithBackoffRetries: 1,
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

		ml.EXPECT().Warn(gomock.Any()).AnyTimes()
		ml.EXPECT().Warn(gomock.Any()).AnyTimes()
		ml.EXPECT().Warn("ScheduleUpdateKeys: failed to get public keys after 1 retries: failed to retrieve keys. Response: , Body: ").AnyTimes()

		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(500 * time.Millisecond)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
		assert.True(t, azjwt.rsakeys.Len() == 0, "expected no public keys to be loaded")
	})
}

// Test we preserve public keys whilst periodically updating them so that token validation does not fail with 403s due to missing keys.
func TestAzureJwtValidator_ScheduleUpdateKeysPreservesRsaKeys(t *testing.T) {
	t.Parallel()

	t.Run("should not drop public keys during key updates", func(t *testing.T) {
		// Generate a valid RSA public key and corresponding JWK
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub := &privateKey.PublicKey
		kid, err := jwtmodels.GenerateJwkKid(pub)
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
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		// Setup a stub HTTP client that always returns the same keys
		client := &http.Client{
			Transport: newStubRoundTripperReadMultiple(
				bytes.NewReader(keysBytes),
				&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
				}),
		}

		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:  "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience: "test-audience",
				Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:    []string{"Test.Role.1", "Test.Role.2"},
			},
			client:  client,
			logger:  logger.NewStdLog("warn"),
			rsakeys: NewPublicKeys(),
		}

		// Preload keys
		require.NoError(t, azjwt.getPublicKeys())

		// Setup test plugin and HTTP server
		plugin := &testPlugin{
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}),
			validator: azjwt,
		}
		server := http.Server{
			Handler: plugin,
		}
		ln, err := newLocalListener()
		require.NoError(t, err)
		defer ln.Close()

		go server.Serve(ln)
		defer server.Close()

		// Start ScheduleUpdateKeys in background
		ctx, cancel := context.WithCancel(context.Background())
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		go azjwt.ScheduleUpdateKeys(ctx, ticker)

		// Generate a valid JWT signed with the private key
		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)

		// Send requests repeatedly while keys are being updated
		clientHTTP := &http.Client{}
		url := "http://" + ln.Addr().String()
		for range 5 {
			req, err := http.NewRequest("GET", url, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+string(token.RawToken))
			resp, err := clientHTTP.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			resp.Body.Close()
			time.Sleep(30 * time.Millisecond)
		}

		cancel()
	})

	t.Run("should return 403 if token is invalid", func(t *testing.T) {
		// Generate a valid RSA public key and corresponding JWK
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub := &privateKey.PublicKey
		kid, err := jwtmodels.GenerateJwkKid(pub)
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
			},
		}
		keysBytes, err := json.Marshal(keys)
		require.NoError(t, err)

		// Setup a stub HTTP client that always returns the same keys
		client := &http.Client{
			Transport: newStubRoundTripperReadMultiple(
				bytes.NewReader(keysBytes),
				&http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
				}),
		}

		azjwt := &AzureJwtValidator{
			config: Config{
				KeysUrl:  "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Audience: "test-audience",
				Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:    []string{"Test.Role.1", "Test.Role.2"},
			},
			client:  client,
			logger:  logger.NewStdLog("warn"),
			rsakeys: NewPublicKeys(),
		}

		// Preload keys
		require.NoError(t, azjwt.getPublicKeys())

		// Setup test plugin and HTTP server
		plugin := &testPlugin{
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}),
			validator: azjwt,
		}
		server := http.Server{
			Handler: plugin,
		}
		ln, err := newLocalListener()
		require.NoError(t, err)
		defer ln.Close()

		go server.Serve(ln)
		defer server.Close()

		// Start ScheduleUpdateKeys in background
		ctx, cancel := context.WithCancel(context.Background())
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		go azjwt.ScheduleUpdateKeys(ctx, ticker)

		// Generate an invalid JWT (e.g., with wrong audience)
		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"wrong-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)

		// Send requests repeatedly while keys are being updated
		clientHTTP := &http.Client{}
		url := "http://" + ln.Addr().String()
		for range 5 {
			req, err := http.NewRequest("GET", url, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+string(token.RawToken))
			resp, err := clientHTTP.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			resp.Body.Close()
			time.Sleep(30 * time.Millisecond)
		}

		cancel()
	})
}
