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
	"strconv"
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
	LogHeaders    []string
}

type AzureJwtPlugin struct {
	next   http.Handler
	config *Config
	client *http.Client
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
		client: &http.Client{
			Timeout: time.Second * 10,
		},
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
			LoggerWARN.Println(valerr)
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

		LogHttp(LoggerWARN, errMsg, azureJwt.config.LogHeaders, http.StatusUnauthorized, req)
		http.Error(rw, errMsg, http.StatusUnauthorized)
	}

	if tokenValid {
		azureJwt.next.ServeHTTP(rw, req)
	} else {
		LogHttp(LoggerWARN, "The token you provided is not valid. Please provide a valid token.", azureJwt.config.LogHeaders, http.StatusForbidden, req)
		http.Error(rw, "The token you provided is not valid. Please provide a valid token.", http.StatusForbidden)
	}
}

func (azureJwt *AzureJwtPlugin) scheduleUpdateKeys(config *Config) {
	for {
		_ = azureJwt.GetPublicKeys(config)
		time.Sleep(15 * time.Minute)
	}
}

func (azureJwt *AzureJwtPlugin) GetPublicKeys(config *Config) error {
	verifyAndSetPublicKey(config.PublicKey)

	if strings.TrimSpace(config.KeysUrl) != "" {
		var body JWKSet
		resp, err := azureJwt.client.Get(config.KeysUrl)

		if err != nil {
			e := fmt.Errorf("failed to load public key from:%v", config.KeysUrl)
			LoggerWARN.Println(e)
			return e
		}
		defer resp.Body.Close()
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			e := fmt.Errorf("failed to read response body from:%v", config.KeysUrl)
			LoggerWARN.Println(e.Error())
			return e
		}

		if resp.StatusCode != http.StatusOK {
			e := fmt.Errorf("failed to retrieve keys. Response: %s, Body: %s", resp.Status, bytes)
			LoggerWARN.Println(e.Error())
			return e
		}

		err = json.Unmarshal(bytes, &body)
		if err != nil {
			e := fmt.Errorf("failed to unmarshal public kyes: %v. Response: %s, Body: %s", err, resp.Status, bytes)
			LoggerWARN.Println(e.Error())
			return e
		}

		keys := body.Keys

		if len(keys) == 0 {
			LoggerWARN.Println("failed to load public key. No keys found from:", config.KeysUrl)
			return fmt.Errorf("failed to load public key. No keys found from:%v", config.KeysUrl)
		}
		for _, key := range keys {
			kid := key.Kid
			e := key.E
			rsakey := new(rsa.PublicKey)
			number, _ := base64.RawURLEncoding.DecodeString(key.N)
			rsakey.N = new(big.Int).SetBytes(number)

			b, err := base64.RawURLEncoding.DecodeString(e)
			if err != nil {
				LoggerWARN.Println("Error parsing key E:", err)
			}

			rsakey.E = int(new(big.Int).SetBytes(b).Uint64())
			rsakeys[kid] = rsakey
		}
	}

	return nil
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

	if _, ok := rsakeys[token.Header.Kid]; !ok {
		return errors.New("invalid public key")
	}

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
		LoggerWARN.Println("Token has expired", time.Unix(tokenExpiration, 0))
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
			var allRolesValid = true
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
				LoggerWARN.Println("missing correct role, found: " + strings.Join(parsedClaims.Roles, ",") + ", expected: " + strings.Join(azureJwt.config.Roles, ","))
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

func LogHttp(logger *log.Logger, message string, headers []string, statusCode int, request *http.Request) {
	var logPayload = make(map[string]string)

	for _, header := range headers {
		logPayload[header] = request.Header.Get(header)
	}

	logPayload["StatusCode"] = strconv.Itoa(statusCode)
	logPayload["Url"] = request.URL.String()
	logPayload["Method"] = request.Method
	logPayload["Error"] = message

	jsonStr, err := json.Marshal(logPayload)

	if err != nil {
		logger.Printf("Error marshaling log payload to JSON: %v\n", err)
		return
	}

	logger.Println(string(jsonStr))
}
