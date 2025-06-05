package azurejwtvalidator

import (
	"crypto/rsa"
	"net/http"
)

type AzureJwtValidator struct {
	client *http.Client
	// Public keys: set if we pass a PublicKey in our config or retrieved via the JWKs url
	rsakeys map[string]*rsa.PublicKey
}

func NewAzureJwtValidator(client *http.Client) *AzureJwtValidator {
	return &AzureJwtValidator{
		client:  client,
		rsakeys: make(map[string]*rsa.PublicKey),
	}
}
