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
		// FIXME: should we use the logger here?
		fmt.Println("No authorization header present")
		return nil, errors.New("no authorization header")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		fmt.Println("not bearer auth scheme")
		return nil, errors.New("not bearer auth scheme")
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		fmt.Println("invalid token format")
		return nil, errors.New("invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Header: %+v", err)
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Payload: %+v", err)
		return nil, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Printf("Signature: %+v", err)
		return nil, errors.New("invalid token")
	}
	jwtToken := jwtmodels.AzureJwt{
		RawToken:   []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature:  signature,
		RawPayload: payload,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		fmt.Printf("JSON HEADER: %+v", err)
		return nil, errors.New("invalid token")
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		fmt.Printf("JSON PAYLOAD: %+v", err)
		return nil, errors.New("invalid token")
	}
	return &jwtToken, nil
}
