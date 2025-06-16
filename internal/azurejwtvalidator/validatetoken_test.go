package azurejwtvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
	"github.com/music-tribe/azadjwtvalidation/internal/logger"
)

func TestAzureJwtValidator_verifyToken(t *testing.T) {
	t.Parallel()

	l := logger.NewStdLog("warn")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &privateKey.PublicKey

	type fields struct {
		config  Config
		client  *http.Client
		logger  logger.Logger
		rsakeys map[string]*rsa.PublicKey
	}
	type args struct {
		jwtToken *jwtmodels.AzureJwt
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "expect invalid if token has expired",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:    []string{"Test.Role.1", "Test.Role.2"},
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(-1*time.Hour),
					[]string{"Test.Role.1", "Test.Role.2"},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					false),
			},
			wantErr:    true,
			wantErrMsg: "token is expired",
		},
		{
			name: "expect invalid if audience is wrong",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:    []string{"Test.Role.1", "Test.Role.2"},
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1", "Test.Role.2"},
					"wrong-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr:    true,
			wantErrMsg: "token audience is wrong",
		},
		{
			name: "expect invalid if issuer is wrong",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:    []string{"Test.Role.1", "Test.Role.2"},
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1", "Test.Role.2"},
					"test-audience",
					"wrong-issuer",
					privateKey,
					true),
			},
			wantErr:    true,
			wantErrMsg: "wrong issuer",
		},
		{
			name: "expect valid if no config roles",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1", "Test.Role.2"},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one config role",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:    []string{"Test.Role.1"},
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1"},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr: false,
		},
		{
			name: "expect valid if we match one config role, matchAllRoles is false",
			fields: fields{
				config: Config{
					Audience: "test-audience",
					Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:    []string{"Test.Role.1", "Test.Role.2"},
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1"},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr: false,
		},
		{
			name: "expect invalid if we match only one config role but matchAllRoles is true",
			fields: fields{
				config: Config{
					Audience:      "test-audience",
					Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:         []string{"Test.Role.1", "Test.Role.2"},
					MatchAllRoles: true,
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{"Test.Role.1"},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr:    true,
			wantErrMsg: "missing correct role",
		},
		{
			name: "expect invalid if we have no roles but we have config roles set",
			fields: fields{
				config: Config{
					Audience:      "test-audience",
					Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:         []string{"Test.Role.1", "Test.Role.2"},
					MatchAllRoles: true,
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr:    true,
			wantErrMsg: "missing correct role",
		},
		{
			name: "expect vailid if we have no roles and no config roles set",
			fields: fields{
				config: Config{
					Audience:      "test-audience",
					Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:         []string{},
					MatchAllRoles: true,
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					[]string{},
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr: false,
		},
		{
			name: "expect invalid if our roles are nil and we have config roles",
			fields: fields{
				config: Config{
					Audience:      "test-audience",
					Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					Roles:         []string{"Test.Role.1", "Test.Role.2"},
					MatchAllRoles: true,
				},
				client: http.DefaultClient,
				logger: l,
				rsakeys: map[string]*rsa.PublicKey{
					"test-key-id": pub,
				},
			},
			args: args{
				jwtToken: generateTestJwt(t,
					time.Now().Add(1*time.Hour),
					nil,
					"test-audience",
					"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
					privateKey,
					true),
			},
			wantErr:    true,
			wantErrMsg: "missing correct role",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			azjwt := &AzureJwtValidator{
				config:  tt.fields.config,
				client:  tt.fields.client,
				logger:  tt.fields.logger,
				rsakeys: tt.fields.rsakeys,
			}
			var err error
			if err = azjwt.verifyToken(tt.args.jwtToken); (err != nil) != tt.wantErr {
				t.Errorf("AzureJwtValidator.verifyToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assert.Equal(t, tt.wantErrMsg, err.Error(), "Expected error message does not match")
			}
		})
	}
}

type JwtClaim struct {
	Roles []string
	jwt.StandardClaims
}

func generateTestJwt(t *testing.T, expiresAt time.Time, roles []string, audience string, issuer string, privKey *rsa.PrivateKey, validateToken bool) *jwtmodels.AzureJwt {
	testClaims := JwtClaim{
		Roles: roles,
		//lint:ignore SA1019 FIXME at a later date. Use RegisteredClaims: https://pkg.go.dev/github.com/golang-jwt/jwt/v4@v4.4.2#example-NewWithClaims-CustomClaimsType
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  audience,
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   "test-subject",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	kid, err := jwtmodels.GenerateJwkKid(&privKey.PublicKey)
	require.NoError(t, err)
	token.Header["kid"] = kid

	signedString, errSignedString := token.SignedString(privKey)
	require.NoError(t, errSignedString)
	token.Signature = signedString

	return convertToAzureJwt(t, signedString, &privKey.PublicKey, validateToken)
}

func convertToAzureJwt(t *testing.T, tokenString string, pub *rsa.PublicKey, validateToken bool) *jwtmodels.AzureJwt {
	parserOptions := []jwt.ParserOption{}
	if !validateToken {
		parserOptions = append(parserOptions, jwt.WithoutClaimsValidation())
	}
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaim{}, func(token *jwt.Token) (any, error) {
		return pub, nil
	}, parserOptions...)
	require.NoError(t, err)
	claims, ok := token.Claims.(*JwtClaim)
	require.True(t, ok)

	azureJwt := &jwtmodels.AzureJwt{
		Header: jwtmodels.AzureJwtHeader{Alg: "RS256", Kid: token.Header["kid"].(string), Typ: "JWT"},
		Payload: jwtmodels.Claims{
			Iat:   json.Number(strconv.FormatInt(claims.IssuedAt, 10)),
			Exp:   json.Number(strconv.FormatInt(claims.ExpiresAt, 10)),
			Iss:   claims.Issuer,
			Aud:   claims.Audience,
			Sub:   claims.Subject,
			Roles: claims.Roles,
		},
		Signature:  []byte(token.Signature),
		RawToken:   []byte(tokenString),
		RawPayload: []byte(token.Raw),
	}

	return azureJwt
}

func publicKeyToBytes(t *testing.T, pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func TestAzureJwtValidator_ValidateToken(t *testing.T) {
	t.Parallel()

	l := logger.NewStdLog("warn")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("expect invalid if we have no matching public key", func(t *testing.T) {
		azjwt := &AzureJwtValidator{
			config: Config{
				Audience: "test-audience",
				Issuer:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
				Roles:    []string{"Test.Role.1", "Test.Role.2"},
			},
			client: http.DefaultClient,
			logger: l,
		}
		err := azjwt.ValidateToken(generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true))
		assert.Error(t, err)
		assert.Equal(t, "invalid public key", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if we use a different private key to sign that doesn't match our public keys", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		// Use a different private key to sign the token
		otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			otherPrivateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "invalid public key", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if we can't verify the token", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		// Use a different private key to sign the token
		otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			otherPrivateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)

		// Set up an invalid public key to simulate a verification failure
		azjwt.rsakeys[token.Header.Kid] = &privateKey.PublicKey

		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "crypto/rsa: verification error", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if token has expired", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(-1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			false)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "token is expired", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if audience is wrong", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"wrong-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "token audience is wrong", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if issuer is wrong", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"wrong-issuer",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "wrong issuer", err.Error(), "Expected error message does not match")
	})

	t.Run("expect valid if no config roles", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1", "Test.Role.2"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.NoError(t, err)
	})

	t.Run("expect valid if we match one config role", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.NoError(t, err)
	})

	t.Run("expect valid if we match one config role, matchAllRoles is false", func(t *testing.T) {
		config := Config{
			PublicKey: string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:  "test-audience",
			Issuer:    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:     []string{"Test.Role.1", "Test.Role.2"},
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.NoError(t, err)
	})

	t.Run("expect invalid if we match only one config role but matchAllRoles is true", func(t *testing.T) {
		config := Config{
			PublicKey:     string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:      "test-audience",
			Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:         []string{"Test.Role.1", "Test.Role.2"},
			MatchAllRoles: true,
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{"Test.Role.1"},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "missing correct role", err.Error(), "Expected error message does not match")
	})

	t.Run("expect invalid if we have no roles but we have config roles set", func(t *testing.T) {
		config := Config{
			PublicKey:     string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:      "test-audience",
			Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:         []string{"Test.Role.1", "Test.Role.2"},
			MatchAllRoles: true,
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "missing correct role", err.Error(), "Expected error message does not match")
	})

	t.Run("expect vailid if we have no roles and no config roles set", func(t *testing.T) {
		config := Config{
			PublicKey:     string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:      "test-audience",
			Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:         []string{},
			MatchAllRoles: true,
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			[]string{},
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.NoError(t, err)
	})

	t.Run("expect invalid if our roles are nil and we have config roles set", func(t *testing.T) {
		config := Config{
			PublicKey:     string(publicKeyToBytes(t, &privateKey.PublicKey)),
			Audience:      "test-audience",
			Issuer:        "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			Roles:         []string{"Test.Role.1", "Test.Role.2"},
			MatchAllRoles: true,
		}
		azjwt := NewAzureJwtValidator(config, http.DefaultClient, l)
		err := azjwt.GetPublicKeys()
		require.NoError(t, err)

		token := generateTestJwt(t,
			time.Now().Add(1*time.Hour),
			nil,
			"test-audience",
			"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
			privateKey,
			true)
		request := httptest.NewRequest("GET", "/testtoken", nil)
		request.Header.Set("Authorization", "Bearer "+string(token.RawToken))
		extractedToken, err := azjwt.ExtractToken(request)
		require.NoError(t, err)
		err = azjwt.ValidateToken(extractedToken)
		assert.Error(t, err)
		assert.Equal(t, "missing correct role", err.Error(), "Expected error message does not match")
	})
}
