package azadjwtvalidation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

type JwtClaim struct {
	Roles []string
	jwt.StandardClaims
}

func TestInvalidPublicKey(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
			KeysUrl:  "",
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, _ := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")
	invalidPublicKey := rsa.PublicKey{N: big.NewInt(0), E: 0}

	_, err := createRequestAndValidateToken(t, azureJwtPlugin, &invalidPublicKey, validToken)

	assert.Error(t, err, "invalid public key")
}

func TestValidTokenFromDifferentTenant(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	_, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")
	tokenFromOtherTenant, _ := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "other_config_rsa")

	_, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, tokenFromOtherTenant)

	assert.Error(t, err, "invalid public key")
}

// Invalid url doesn't exist
func TestInvalidKeysUrl(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
			KeysUrl:  "https://invalid-url",
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	_, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.Error(t, err, "failed to load public key from:https://invalid-url")
}

// Invalid url exists but is incorrect
func TestIncorrectKeysUrl(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
			KeysUrl:  "https://google.com",
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	_, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.Error(t, err, "failed to load public key. No keys found from:https://google.com")
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
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

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
	validToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "audience1", azureJwtPlugin.config.Issuer, "config_rsa")

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
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, invalidToken)

	assert.Contains(t, err.Error(), "token is expired")
	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestMissingAuthorizationHeaderToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	extractedToken, err := createRequestWithoutAuthorizationHeader(t, azureJwtPlugin)

	assert.Equal(t, err.Error(), "no authorization header")
	assert.Nil(t, extractedToken)
}

func TestNotBearerToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(-time.Hour)
	invalidToken, _ := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	extractedToken, err := createRequestWithAuthorizationHeaderButNotBearerToken(t, azureJwtPlugin, invalidToken)

	assert.Equal(t, err.Error(), "not bearer auth scheme")
	assert.Nil(t, extractedToken)
}

func TestInvalidIssuer(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "correct-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	token, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, azureJwtPlugin.config.Audience, "invalid-issuer", "config_rsa")

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, token)

	assert.Equal(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
	assert.Equal(t, "invalid-issuer", extractedToken.Payload.Iss)
	assert.Error(t, err, "wrong issuer")
}

func TestInvalidTokenFormat(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "admin",
			Roles:    []string{"test_role_1"},
		},
	}

	tokenWithInvalidFormat := "some_format"
	extractedToken, err := createRequestWithInvalidBearerTokenFormat(t, azureJwtPlugin, tokenWithInvalidFormat)

	assert.Equal(t, err.Error(), "invalid token format")
	assert.Nil(t, extractedToken)
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
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "wrong audience", azureJwtPlugin.config.Issuer, "config_rsa")

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
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "wrong-audience", azureJwtPlugin.config.Issuer, "config_rsa")

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
	invalidToken, publicKey := generateTestToken(expiresAt, azureJwtPlugin.config.Roles, "right-audience1", azureJwtPlugin.config.Issuer, "config_rsa")

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
	validToken, publicKey := generateTestToken(expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

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
	validToken, publicKey := generateTestToken(expiresAt, []string{"test_role_2"}, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

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
	validToken, publicKey := generateTestToken(expiresAt, nil, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.NoError(t, err)
	assert.Equal(t, azureJwtPlugin.config.Issuer, extractedToken.Payload.Iss)
}

func TestRolesInConfigButNotInToken(t *testing.T) {
	azureJwtPlugin := AzureJwtPlugin{
		config: &Config{
			Issuer:   "random-issuer",
			Audience: "tenant",
			Roles:    []string{"test_role_1", "test_role_2"},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	validToken, publicKey := generateTestToken(expiresAt, nil, azureJwtPlugin.config.Audience, azureJwtPlugin.config.Issuer, "config_rsa")

	extractedToken, err := createRequestAndValidateToken(t, azureJwtPlugin, publicKey, validToken)

	assert.Error(t, err, "missing correct role")
	assert.NotEqual(t, azureJwtPlugin.config.Roles, extractedToken.Payload.Roles)
}

func TestHttpErrorLoggingWithLogHeaderDisabled(t *testing.T) {
	// Set up a buffer to capture the log output
	var buf bytes.Buffer
	testLogger := log.New(&buf, "", log.LstdFlags)

	// Set up a request with headers
	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", "dummytoken")
	request.Header.Set("X-Request-Id", "1234")

	// Log the error
	LogHttp(testLogger, "test error message", nil, http.StatusForbidden, request)

	// Check the output
	assert.Contains(t, buf.String(), "\"Error\":\"test error message\"")
	assert.NotContains(t, buf.String(), "\"Authorization\":\"dummytoken\"")
	assert.NotContains(t, buf.String(), "\"X-Request-Id\":\"1234\"")
	assert.Contains(t, buf.String(), "\"Method\":\"GET\"")
	assert.Contains(t, buf.String(), "\"StatusCode\":\"403\"")
	assert.Contains(t, buf.String(), "\"Url\":\"/testtoken\"")
}

func TestHttpErrorLoggingWithLogHeaderEnabled(t *testing.T) {
	// Set up a buffer to capture the log output
	var buf bytes.Buffer
	testLogger := log.New(&buf, "", log.LstdFlags)

	// Set up a request with headers
	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", "dummytoken")
	request.Header.Set("X-Request-Id", "1234")

	// Set list of headers to log
	headers := []string{"X-Request-Id"}

	// Log the error
	LogHttp(testLogger, "test error message", headers, http.StatusForbidden, request)

	// Check the output
	log.Println(buf.String())
	assert.Contains(t, buf.String(), "\"Error\":\"test error message\"")
	assert.NotContains(t, buf.String(), "\"Authorization\":\"dummytoken\"")
	assert.Contains(t, buf.String(), "\"X-Request-Id\":\"1234\"")
	assert.Contains(t, buf.String(), "\"Method\":\"GET\"")
	assert.Contains(t, buf.String(), "\"StatusCode\":\"403\"")
	assert.Contains(t, buf.String(), "\"Url\":\"/testtoken\"")
}

func createRequestAndValidateToken(t *testing.T, azureJwtPlugin AzureJwtPlugin, publicKey *rsa.PublicKey, token string) (*AzureJwt, error) {
	err := azureJwtPlugin.GetPublicKeys(&Config{
		PublicKey: string(PublicKeyToBytes(publicKey)),
		KeysUrl:   azureJwtPlugin.config.KeysUrl,
	})

	if err != nil {
		return nil, err
	}

	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)
	assert.NoError(t, err)

	err = azureJwtPlugin.ValidateToken(extractedToken)

	return extractedToken, err
}

func createRequestWithoutAuthorizationHeader(t *testing.T, azureJwtPlugin AzureJwtPlugin) (*AzureJwt, error) {
	request := httptest.NewRequest("GET", "/testtoken", nil)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)

	return extractedToken, err
}

func createRequestWithAuthorizationHeaderButNotBearerToken(t *testing.T, azureJwtPlugin AzureJwtPlugin, token string) (*AzureJwt, error) {
	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", token)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)

	return extractedToken, err
}

func createRequestWithInvalidBearerTokenFormat(t *testing.T, azureJwtPlugin AzureJwtPlugin, token string) (*AzureJwt, error) {
	request := httptest.NewRequest("GET", "/testtoken", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	extractedToken, err := azureJwtPlugin.ExtractToken(request)

	return extractedToken, err
}

func generateTestToken(expiresAt time.Time, roles []string, audience string, issuer string, publicKeyId string) (testtoken string, publicKey *rsa.PublicKey) {
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
	token.Header["kid"] = publicKeyId

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
