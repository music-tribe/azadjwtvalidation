package azurejwtvalidator

import (
	"context"
	"fmt"
	"time"
)

// Periodically updates the public keys used for JWT validation.
func (azjwt *AzureJwtValidator) ScheduleUpdateKeys(ctx context.Context, ticker *time.Ticker) {
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := azjwt.GetPublicKeysWithOptionalBackoffRetry(ctx)
			if err != nil {
				azjwt.logger.Warn(fmt.Sprintf("ScheduleUpdateKeys: %v", err))
			}
		}
	}
}
