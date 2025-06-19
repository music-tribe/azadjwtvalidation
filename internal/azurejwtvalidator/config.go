package azurejwtvalidator

import "fmt"

// Configuration for the Azure JWT Validator.
// Ideally, we would use go-playground/validator/v10 to validate the configuration,
// but this package imports syscall which is not allowed in Yaegi used by Traefik.
type Config struct {
	PublicKey                    string // `validate:"required_without=KeysUrl"`
	KeysUrl                      string // `validate:"required_without=PublicKey,omitempty,http_url"`
	Issuer                       string // `validate:"required,http_url"`
	Audience                     string // `validate:"required"`
	Roles                        []string
	MatchAllRoles                bool
	UpdateKeysEveryMinutes       int    // `validate:"required,min=5,max=2880"` // 2 days in minutes, Reasonable frequency is 24 hours: https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#validate-signature
	UpdateKeysWithBackoffRetries uint64 // Number of retries for backoff when fetching keys. Default 0 is no retries.
}

func (c *Config) validate() error {
	if c.UpdateKeysEveryMinutes == 0 {
		c.UpdateKeysEveryMinutes = 1440 // Default to 24 hours
	}
	if c.PublicKey == "" && c.KeysUrl == "" {
		return fmt.Errorf("either PublicKey or KeysUrl must be provided")
	}
	if c.Issuer == "" {
		return fmt.Errorf("Error:Field validation for 'Issuer' failed on the 'required' tag")
	}
	if c.Audience == "" {
		return fmt.Errorf("Error:Field validation for 'Audience' failed on the 'required' tag")
	}
	if c.UpdateKeysEveryMinutes < 5 {
		return fmt.Errorf("Error:Field validation for 'UpdateKeysEveryMinutes' failed on the 'min' tag")
	}

	if c.UpdateKeysEveryMinutes > 2880 {
		return fmt.Errorf("Error:Field validation for 'UpdateKeysEveryMinutes' failed on the 'max' tags")
	}
	return nil
}
