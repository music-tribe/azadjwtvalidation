package azurejwtvalidator

import "github.com/go-playground/validator/v10"

type Config struct {
	PublicKey                    string `validate:"required_without=KeysUrl"`
	KeysUrl                      string `validate:"required_without=PublicKey,omitempty,http_url"`
	Issuer                       string `validate:"required,http_url"`
	Audience                     string `validate:"required"`
	Roles                        []string
	MatchAllRoles                bool
	UpdateKeysEveryMinutes       int    `validate:"required,min=5,max=2880"` // 2 days in minutes, Reasonable frequency is 24 hours: https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#validate-signature
	UpdateKeysWithBackoffRetries uint64 // Number of retries for backoff when fetching keys. Default 0 is no retries.
}

func (c *Config) validate() error {
	if c.UpdateKeysEveryMinutes == 0 {
		c.UpdateKeysEveryMinutes = 1440 // Default to 24 hours
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(c)
	if err != nil {
		return err
	}
	return nil
}
