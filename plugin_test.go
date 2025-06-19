package azadjwtvalidation

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/music-tribe/azadjwtvalidation/internal/logger"
	"github.com/stretchr/testify/assert"
)

type JwtClaim struct {
	Roles []string
	jwt.StandardClaims
}

func TestHttpErrorLoggingWithLogHeaderDisabled(t *testing.T) {
	// Set up a buffer to capture the log output
	var buf bytes.Buffer
	testLogger := logger.NewLogWithBuffer("DEBUG", &buf)

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
	testLogger := logger.NewLogWithBuffer("DEBUG", &buf)

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
