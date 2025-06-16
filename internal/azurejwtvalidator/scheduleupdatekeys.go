package azurejwtvalidator

import (
	"context"
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
			// Do we need to do anything with the error here? We are currently logging an error if this fails
			_ = azjwt.GetPublicKeys()
		}
	}
}
