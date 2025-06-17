package azurejwtvalidator

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
)

// Periodically updates the public keys used for JWT validation.
func (azjwt *AzureJwtValidator) ScheduleUpdateKeys(ctx context.Context, ticker *time.Ticker) {
	defer ticker.Stop()

	withBackoffOperation := func() {
		err := azjwt.getPublicKeysWithBackoffRetry(ctx, azjwt.config.UpdateKeysWithBackoffRetries)
		if err != nil {
			azjwt.logger.Warn(fmt.Sprintf("ScheduleUpdateKeys: failed to get public keys after %d retries: %v", azjwt.config.UpdateKeysWithBackoffRetries, err))
		}
	}
	withoutBackoffOperation := func() {
		// Do we need to do anything with the error here? We are currently logging an error if this fails
		_ = azjwt.GetPublicKeys()
	}

	var operation func()
	if azjwt.config.UpdateKeysWithBackoffRetries > 0 {
		operation = withBackoffOperation
	} else {
		operation = withoutBackoffOperation
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operation()
		}
	}
}

func (azjwt *AzureJwtValidator) getPublicKeysWithBackoffRetry(ctx context.Context, maxRetries uint) error {
	operation := func() (string, error) {
		return "", azjwt.GetPublicKeys()
	}
	_, err := backoff.Retry(ctx, operation, backoff.WithMaxTries(maxRetries), backoff.WithBackOff(backoff.NewExponentialBackOff()))
	if err != nil {
		return err
	}
	return nil
}
