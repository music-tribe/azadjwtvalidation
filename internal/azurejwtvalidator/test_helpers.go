package azurejwtvalidator

import (
	"errors"
	"io"
	"net"
	"net/http"
)

type stubRoundTripper struct {
	response *http.Response
	err      error
}

// newStubRoundTripper creates a new stub RoundTripper that returns the provided response and error.
func newStubRoundTripper(response *http.Response, err error) *stubRoundTripper {
	return &stubRoundTripper{response, err}
}
func (sr *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return sr.response, sr.err
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

// stubRoundTripperReadMultiple is a RoundTripper that returns a response with a body that can be read multiple times.
type stubRoundTripperReadMultiple struct {
	body     io.ReadSeeker
	response *http.Response
}

func newStubRoundTripperReadMultiple(body io.ReadSeeker, response *http.Response) *stubRoundTripperReadMultiple {
	return &stubRoundTripperReadMultiple{body, response}
}

func (sr *stubRoundTripperReadMultiple) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := sr.body.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// Defensive copy to avoid data races when the stub is reused.
	resp := *sr.response
	resp.Body = io.NopCloser(sr.body)
	return &resp, nil
}

// testPlugin mimics the traefik middleware and uses AzureJwtValidator to validate JWT tokens in HTTP requests.
type testPlugin struct {
	next      http.Handler
	validator *AzureJwtValidator
}

func (p *testPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	token, err := p.validator.ExtractToken(req)

	if err == nil {
		valerr := p.validator.ValidateToken(token)
		if valerr == nil {
			tokenValid = true
		}
	} else {
		errMsg := ""

		switch err.Error() {
		case "no authorization header":
			errMsg = "No token provided. Please use Authorization header to pass a valid token."
		case "not bearer auth scheme":
			errMsg = "Token provided on Authorization header is not a bearer token. Please provide a valid bearer token."
		case "invalid token format":
			errMsg = "The format of the bearer token provided on Authorization header is invalid. Please provide a valid bearer token."
		case "invalid token":
			errMsg = "The token provided is invalid. Please provide a valid bearer token."
		}

		http.Error(rw, errMsg, http.StatusUnauthorized)
	}

	if tokenValid {
		p.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, "The token you provided is not valid. Please provide a valid token.", http.StatusForbidden)
	}
}
func newLocalListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
