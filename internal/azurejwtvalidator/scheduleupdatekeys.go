package azurejwtvalidator

import (
	"context"
	"fmt"
	"time"
)

// ScheduleUpdateKeysAsync starts a goroutine that periodically updates the public keys used for JWT validation.
func (azjwt *AzureJwtValidator) ScheduleUpdateKeysAsync(ctx context.Context) {
	if azjwt.config.KeysUrl == "" {
		azjwt.logger.Info("No KeysUrl provided, skipping periodic key updates")
		return
	}
	azjwt.logger.Info(fmt.Sprintf("Scheduling periodic update of public keys every %d minutes", azjwt.config.UpdateKeysEveryMinutes))
	go azjwt.scheduleUpdateKeys(ctx, time.NewTicker(time.Duration(azjwt.config.UpdateKeysEveryMinutes)*time.Minute))
}

// Periodically updates the public keys used for JWT validation.
func (azjwt *AzureJwtValidator) scheduleUpdateKeys(ctx context.Context, ticker *time.Ticker) {
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := azjwt.GetPublicKeysWithOptionalBackoffRetry(ctx)
			if err != nil {
				azjwt.logger.Warn(fmt.Sprintf("scheduleUpdateKeys: %v", err))
			}
		}
	}
}
