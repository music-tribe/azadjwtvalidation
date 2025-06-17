package azurejwtvalidator

import (
	"context"
	"fmt"
	"time"
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
