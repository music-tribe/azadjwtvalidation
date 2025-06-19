package azadjwtvalidation

// FIXME: this could be renamed to plugin.go

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/music-tribe/azadjwtvalidation/internal/azurejwtvalidator"
	"github.com/music-tribe/azadjwtvalidation/internal/logger"
)

type Config struct {
	PublicKey                    string
	KeysUrl                      string
	Issuer                       string
	Audience                     string
	Roles                        []string
	MatchAllRoles                bool
	UpdateKeysEveryMinutes       int
	UpdateKeysWithBackoffRetries uint64
	LogLevel                     string
	LogHeaders                   []string
}

type AzureJwtPlugin struct {
	next      http.Handler
	config    *Config
	validator *azurejwtvalidator.AzureJwtValidator
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
	l := logger.NewStdLog(config.LogLevel)

	validator := azurejwtvalidator.NewAzureJwtValidator(
		azurejwtvalidator.Config{
			PublicKey:                    config.PublicKey,
			KeysUrl:                      config.KeysUrl,
			Issuer:                       config.Issuer,
			Audience:                     config.Audience,
			Roles:                        config.Roles,
			MatchAllRoles:                config.MatchAllRoles,
			UpdateKeysEveryMinutes:       config.UpdateKeysEveryMinutes,
			UpdateKeysWithBackoffRetries: config.UpdateKeysWithBackoffRetries,
		},
		&http.Client{
			Timeout: time.Second * 10,
		},
		l)

	// Set up the initial public keys before we start
	// Ensure we return an error if we fail
	// This will disable the plugin & any routes dependent on the plugin: https://github.com/traefik/plugindemo?tab=readme-ov-file#usage
	err := validator.GetPublicKeysWithOptionalBackoffRetry(ctx)
	if err != nil {
		l.Warn("failed to start azadjwtvalidation plugin! Disabling plugin")
		return nil, err
	}

	go validator.ScheduleUpdateKeys(ctx, time.NewTicker(time.Duration(config.UpdateKeysEveryMinutes)*time.Minute))

	plugin := &AzureJwtPlugin{
		next:      next,
		config:    config,
		validator: validator,
	}

	l.Info("azadjwtvalidation plugin started")

	return plugin, nil
}

func (azureJwt *AzureJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	tokenValid := false

	token, err := azureJwt.validator.ExtractToken(req)

	if err == nil {
		valerr := azureJwt.validator.ValidateToken(token)
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
