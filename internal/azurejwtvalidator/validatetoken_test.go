package azurejwtvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
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
					privateKey),
			},
			wantErr:    true,
			wantErrMsg: "token audience is wrong",
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
	jwt.RegisteredClaims
}

func generateTestJwt(t *testing.T, expiresAt time.Time, roles []string, audience string, issuer string, privKey *rsa.PrivateKey) *jwtmodels.AzureJwt {
	testClaims := JwtClaim{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "test-subject",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	token.Header["kid"] = publicKeyToBytes(t, &privKey.PublicKey)

	signedString, errSignedString := token.SignedString(privKey)
	require.NoError(t, errSignedString)
	token.Signature = signedString

	return convertToAzureJwt(t, signedString, &privKey.PublicKey)
}

func convertToAzureJwt(t *testing.T, tokenString string, pub *rsa.PublicKey) *jwtmodels.AzureJwt {
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaim{}, func(token *jwt.Token) (any, error) {
		return pub, nil
	})
	require.NoError(t, err)
	claims, ok := token.Claims.(*JwtClaim)
	require.True(t, ok)

	aud := ""
	if len(claims.Audience) != 0 {
		aud = claims.Audience[0] // Use the first audience if multiple are present
	}
	azureJwt := &jwtmodels.AzureJwt{
		Header: jwtmodels.AzureJwtHeader{Alg: "RS256", Kid: token.Header["kid"].(string), Typ: "JWT"},
		Payload: jwtmodels.Claims{
			Iat:   json.Number(strconv.FormatInt(claims.IssuedAt.Unix(), 10)),
			Exp:   json.Number(strconv.FormatInt(claims.ExpiresAt.Unix(), 10)),
			Iss:   claims.Issuer,
			Aud:   aud,
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
