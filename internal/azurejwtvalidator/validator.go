package azurejwtvalidator

import (
	"crypto/rsa"
	"net/http"
)

type AzureJwtValidator struct {
	config Config
	client *http.Client
	// Public keys: set if we pass a PublicKey in our config or retrieved via the JWKs url
	rsakeys map[string]*rsa.PublicKey
}

func NewAzureJwtValidator(config Config, client *http.Client) *AzureJwtValidator {
	if err := config.validate(); err != nil {
		panic(err)
	}

	return &AzureJwtValidator{
		config:  config,
		client:  client,
		rsakeys: make(map[string]*rsa.PublicKey),
	}
}
