package azurejwtvalidator

import (
	"bytes"
	"context"
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
			client: http.DefaultClient,
			logger: logger.NewStdLog("warn"),
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
			logger: logger.NewStdLog("warn"),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
		assert.NotNil(t, azjwt.rsakeys)
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
			client: http.DefaultClient,
			logger: ml,
		}

		ml.EXPECT().Warn("failed to load public key from:https://jwks.keys").AnyTimes()

		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		ticker := time.NewTicker(100 * time.Millisecond)

		azjwt.ScheduleUpdateKeys(ctx, ticker)
		assert.Empty(t, azjwt.rsakeys)
	})
}
