package azurejwtvalidator

import (
	"net/http"

	"github.com/music-tribe/azadjwtvalidation/internal/logger"
)

type AzureJwtValidator struct {
	config Config
	client *http.Client
	logger logger.Logger
	// Public keys: set if we pass a PublicKey in our config or retrieved via the JWKs url
	rsakeys *PublicKeys
}

func NewAzureJwtValidator(config Config, client *http.Client, logger logger.Logger) *AzureJwtValidator {
	if err := config.validate(); err != nil {
		panic(err)
	}

	return &AzureJwtValidator{
		config:  config,
		client:  client,
		logger:  logger,
		rsakeys: NewPublicKeys(),
	}
}
