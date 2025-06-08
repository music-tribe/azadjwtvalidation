package azurejwtvalidator

import "github.com/go-playground/validator/v10"

type Config struct {
	PublicKey     string `validate:"required_without=KeysUrl"`
	KeysUrl       string `validate:"required_without=PublicKey,omitempty,http_url"`
	Issuer        string `validate:"required,http_url"`
	Audience      string `validate:"required"`
	Roles         []string
	MatchAllRoles bool
}

func (c *Config) validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(c)
	if err != nil {
		return err
	}
	return nil
}
