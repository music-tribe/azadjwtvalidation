package azadjwtvalidation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

type JwtClaim struct {
	Roles []string
	jwt.StandardClaims
}

func TestValidToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.NoError(t, err)
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestValidTokenWithMultipleAudiences(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "audience1,audience2",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "audience1", azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.NoError(t, err)
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestExpiredToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(-time.Hour)
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)

	assert.Contains(t, err.Error(), "token is expired")
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestWrongAudienceToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "right-audience",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "wrong audience", azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)

	assert.EqualError(t, err, "token audience is wrong")
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestWrongAudienceInMultipleAudiences(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "right-audience1,right-audience2",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "wrong-audience", azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)

	assert.EqualError(t, err, "token audience is wrong")
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestCorrectAudienceInMultipleAudiences(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "right-audience1,right-audience2",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "right-audience1", azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)

	assert.Equal(t, err, nil)
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestMissingRolesInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "tenant",
			Roles:    []string{"test_role_1", "test_role_2"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.NoError(t, err)

	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestOneRoleInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:        "random-issuer",
			Audience:      "tenant",
			Roles:         []string{"test_role_1", "test_role_2"},
			MatchAllRoles: true,
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.EqualError(t, err, "missing correct role")

	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestNoRolesInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "tenant",
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, nil, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer)

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.NoError(t, err)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func createRequestAndValidateToken(t *testing.T, azureJwtPlugin AzureJwtPlugin, publicKey *rsa.PublicKey, token string) (*AzureJwt, error) {
	azureJwtPlugin.GetPublicKeys(&Config{
		PublicKey: string(PublicKeyToBytes(publicKey)),
	})

	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)
	assert.NoError(t, err)

	err = azureJwtPlugin.ValidateToken(extractedToken)

	return extractedToken, err
}

func generateTestToken(expiresAt time.Time, roles []string, audience string, issuer string) (testtoken string, publicKey *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	testClaims := &JwtClaim{
		Roles: roles,
		StandardClaims: jwt.StandardClaims{
			Audience:  audience,
			Issuer:    issuer,
			ExpiresAt: expiresAt.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	token.Header["kid"] = "config_rsa"

	signedString, errSignedString := token.SignedString(privateKey)

	if errSignedString != nil {
		panic(errSignedString)
	}

	return signedString, &privateKey.PublicKey
}

func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}
