package azurejwtvalidator

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/music-tribe/azadjwtvalidation/internal/jwtmodels"
)

func (azjwt *AzureJwtValidator) ExtractToken(request *http.Request) (*jwtmodels.AzureJwt, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		azjwt.logger.Warn("No authorization header present")
		return nil, errors.New("no authorization header")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		azjwt.logger.Warn("Not bearer auth scheme")
		return nil, errors.New("not bearer auth scheme")
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		azjwt.logger.Warn("Invalid token format")
		return nil, errors.New("invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("Header: %+v", err))
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("Payload: %+v", err))
		return nil, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("Signature: %+v", err))
		return nil, errors.New("invalid token")
	}
	jwtToken := jwtmodels.AzureJwt{
		RawToken:   []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature:  signature,
		RawPayload: payload,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("JSON HEADER: %+v", err))
		return nil, errors.New("invalid token")
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		azjwt.logger.Warn(fmt.Sprintf("JSON PAYLOAD: %+v", err))
		return nil, errors.New("invalid token")
	}
	return &jwtToken, nil
}
