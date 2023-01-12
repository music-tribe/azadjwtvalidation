package azadjwtvalidation

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var rsakeys map[string]*rsa.PublicKey

type Config struct {
	PublicKey     string
	KeysUrl       string
	Issuer        string
	Audience      string
	Roles         []string
	MatchAllRoles bool
	LogLevel      string
}

type AzureJwtPlugin struct {
	next   http.Handler
	config *Config
}

var (
	LoggerINFO  = log.New(io.Discard, "INFO: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerDEBUG = log.New(io.Discard, "DEBUG: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerWARN  = log.New(io.Discard, "WARN: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func CreateConfig() *Config {
	return &Config{}
}

// New created a new HeaderMatch plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	LoggerWARN.SetOutput(os.Stdout)

	switch config.LogLevel {
	case "INFO":
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	}

	if len(config.Audience) == 0 {
		return nil, fmt.Errorf("configuration incorrect, missing audience")
	}

	if strings.TrimSpace(config.Issuer) == "" {
		return nil, fmt.Errorf("configuration incorrect, missing issuer")
	}

	if strings.TrimSpace(config.KeysUrl) == "" && strings.TrimSpace(config.PublicKey) == "" {
		return nil, fmt.Errorf("configuration incorrect, missing either a JWKS url or a static public key")
	}

	plugin := &AzureJwtPlugin{
		next:   next,
		config: config,
	}

	go plugin.scheduleUpdateKeys(config)

	return plugin, nil
}

func (azureJwt *AzureJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	token, err := azureJwt.ExtractToken(req)

	if err == nil {
		valerr := azureJwt.ValidateToken(token)
		if valerr == nil {
			LoggerDEBUG.Println("Accepted request")
			tokenValid = true
		} else {
			LoggerDEBUG.Println(valerr)
		}
	} else {
		errMsg := ""

		switch err.Error() {
		case "no_header_token":
			errMsg = "No token provided. Please use Authorization header to pass a valid token."
		case "no_bearer_token":
			errMsg = "Token provided on Authorization header is not a bearer token. Please provide a valid bearer token."
		case "invalid_token_format":
			errMsg = "The format of the bearer token provided on Authorization header is invalid. Please provide a valid bearer token."
		}

		http.Error(rw, errMsg, http.StatusUnauthorized)
		LoggerDEBUG.Println(err)
	}

	if tokenValid {
		azureJwt.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, "The token you provided is not valid. Please provide a valid token.", http.StatusForbidden)
	}
}

func (azureJwt *AzureJwtPlugin) scheduleUpdateKeys(config *Config) {
	for {
		azureJwt.GetPublicKeys(config)
		time.Sleep(15 * time.Minute)
	}
}

func (azureJwt *AzureJwtPlugin) GetPublicKeys(config *Config) {
	verifyAndSetPublicKey(config.PublicKey)

	if strings.TrimSpace(config.KeysUrl) != "" {
		var body map[string]interface{}
		resp, err := http.Get(config.KeysUrl)

		if err != nil {
			LoggerWARN.Println("failed to load public key from:", config.KeysUrl)
		} else {
			json.NewDecoder(resp.Body).Decode(&body)
			for _, bodykey := range body["keys"].([]interface{}) {
				key := bodykey.(map[string]interface{})
				kid := key["kid"].(string)
				e := key["e"].(string)
				rsakey := new(rsa.PublicKey)
				number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
				rsakey.N = new(big.Int).SetBytes(number)

				b, err := base64.RawURLEncoding.DecodeString(e)
				if err != nil {
					log.Fatalf("Error parsing key E: %v", err)
				}

				rsakey.E = int(new(big.Int).SetBytes(b).Uint64())
				rsakeys[kid] = rsakey
			}
		}
	}
}

func verifyAndSetPublicKey(publicKey string) error {
	rsakeys = make(map[string]*rsa.PublicKey)

	if strings.TrimSpace(publicKey) != "" {
		pubPem, _ := pem.Decode([]byte(publicKey))
		if pubPem == nil {
			return fmt.Errorf("public key could not be decoded")
		}
		if pubPem.Type != "RSA PUBLIC KEY" {
			return fmt.Errorf("public key format invalid")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse RSA public key")
		}

		if pubKey, ok := parsedKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("unable to convert RSA public key")
		} else {
			rsakeys["config_rsa"] = pubKey
		}
	}

	return nil
}

func (azureJwt *AzureJwtPlugin) ExtractToken(request *http.Request) (*AzureJwt, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		fmt.Println("No header token")
		return nil, errors.New("no_header_token")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		fmt.Println("No bearer token")
		return nil, errors.New("no_bearer_token")
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		fmt.Println("invalid token format")
		return nil, errors.New("invalid_token_format")
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
	jwtToken := AzureJwt{
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

func (azureJwt *AzureJwtPlugin) ValidateToken(token *AzureJwt) error {
	hash := sha256.Sum256(token.RawToken)

	err := rsa.VerifyPKCS1v15(rsakeys[token.Header.Kid], crypto.SHA256, hash[:], token.Signature)
	if err != nil {
		return err
	}

	if err := azureJwt.VerifyToken(token); err != nil {
		return err
	}

	var claims Claims
	if err := json.Unmarshal(token.RawPayload, &claims); err != nil {
		return err
	}

	return nil
}

func (azureJwt *AzureJwtPlugin) VerifyToken(jwtToken *AzureJwt) error {
	tokenExpiration, err := jwtToken.Payload.Exp.Int64()
	if err != nil {
		return err
	}

	if tokenExpiration < time.Now().Unix() {
		LoggerDEBUG.Println("Token has expired", time.Unix(tokenExpiration, 0))
		return errors.New("token is expired")
	}

	err = azureJwt.validateClaims(&jwtToken.Payload)
	if err != nil {
		return err
	}

	return nil
}

func (azureJwt *AzureJwtPlugin) validateClaims(parsedClaims *Claims) error {

	if !strings.Contains(azureJwt.config.Audience, parsedClaims.Aud) {
		// if parsedClaims.Aud != azureJwt.config.Audience {
		return errors.New("token audience is wrong")
	}

	if parsedClaims.Iss != azureJwt.config.Issuer {
		return errors.New("wrong issuer")
	}

	if parsedClaims.Roles != nil {
		if len(azureJwt.config.Roles) > 0 {
			var allRolesValid bool = true
			if !azureJwt.config.MatchAllRoles {
				allRolesValid = false
			}

			for _, role := range azureJwt.config.Roles {
				roleValid := parsedClaims.isValidForRole(role)
				if azureJwt.config.MatchAllRoles && !roleValid {
					allRolesValid = false
					break
				}
				if !azureJwt.config.MatchAllRoles && roleValid {
					allRolesValid = true
					break
				}
			}

			if !allRolesValid {
				LoggerDEBUG.Println("missing correct role, found: " + strings.Join(parsedClaims.Roles, ",") + ", expected: " + strings.Join(azureJwt.config.Roles, ","))
				return errors.New("missing correct role")
			}
		}
	} else if len(azureJwt.config.Roles) > 0 {
		return errors.New("missing correct role")
	}

	return nil
}

func (claims *Claims) isValidForRole(configRole string) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == configRole {
			LoggerDEBUG.Println("Match:", parsedRole, configRole)
			return true
		} else {
			LoggerDEBUG.Println("No match:", parsedRole, configRole)
		}
	}

	return false
}
