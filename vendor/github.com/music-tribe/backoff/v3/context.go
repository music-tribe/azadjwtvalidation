package backoff

import (
	"context"
	"time"
)

// BackOffContext is a backoff policy that stops retrying after the context
// is canceled.
type BackOffContext interface { // nolint: golint
	BackOff
	Context() context.Context
}

type backOffContext struct {
	BackOff
	ctx context.Context
}

// WithContext returns a BackOffContext with context ctx
//
// ctx must not be nil
func WithContext(b BackOff, ctx context.Context) BackOffContext { // nolint: golint
	if ctx == nil {
		panic("nil context")
	}

	if b, ok := b.(*backOffContext); ok {
		return &backOffContext{
			BackOff: b.BackOff,
			ctx:     ctx,
		}
	}

	return &backOffContext{
		BackOff: b,
		ctx:     ctx,
	}
}

func getContext(b BackOff) context.Context {
	if cb, ok := b.(BackOffContext); ok {
		return cb.Context()
	}
	if tb, ok := b.(*backOffTries); ok {
		return getContext(tb.delegate)
	}
	return context.Background()
}

func (b *backOffContext) Context() context.Context {
	return b.ctx
}

func (b *backOffContext) NextBackOff() time.Duration {
	select {
	case <-b.ctx.Done():
		return Stop
	default:
	}
	next := b.BackOff.NextBackOff()
	if deadline, ok := b.ctx.Deadline(); ok && deadline.Sub(time.Now()) < next { // nolint: gosimple
		return Stop
	}
	return next
}

func (b *backOffContext) Reset() {
	b.BackOff.Reset()
}
