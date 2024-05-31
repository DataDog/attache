package retry

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

type RetryableFunc func() error

type Config struct {
	maxAttempts  int
	initialDelay time.Duration
	logger       *zap.Logger
	maxJitter    time.Duration
}

type Option func(*Config)

// MaxAttempts is the total number of attempts including the initial attempt.
func MaxAttempts(maxAttempts int) Option {
	return func(c *Config) {
		c.maxAttempts = maxAttempts
	}
}

// MaxJitter the maximum amount of time between [0, maxJitter] to add to a delay.
func MaxJitter(maxJitter time.Duration) Option {
	return func(c *Config) {
		c.maxJitter = maxJitter
	}
}

func InitialDelay(initialDelay time.Duration) Option {
	return func(c *Config) {
		c.initialDelay = initialDelay
	}
}

func Logger(logger *zap.Logger) Option {
	return func(c *Config) {
		c.logger = logger
	}
}

// Do will perform N attempts to execute RetryableFunc.
func Do(ctx context.Context, retryable RetryableFunc, opts ...Option) error {
	config := &Config{
		maxAttempts:  3,
		initialDelay: 200 * time.Millisecond,
		maxJitter:    100 * time.Millisecond,
		logger:       zap.NewNop(),
	}

	for _, opt := range opts {
		opt(config)
	}

	var attempt int

	delay := calcDelayForNextRetry(attempt, config.initialDelay, config.maxJitter)
	ticker := time.NewTicker(delay)

	var err error
	for attempt < config.maxAttempts {
		attempt++
		err = retryable()
		if err != nil {
			retryDelay := calcDelayForNextRetry(attempt, config.initialDelay, config.maxJitter)
			config.logger.Debug("retry failed",
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Duration("retry_delay", retryDelay))

			// on the last attempt we return the error right away rather than waiting to return
			if attempt < config.maxAttempts {
				ticker.Reset(retryDelay)
				select {
				case <-ctx.Done():
					e := err.Error()
					return fmt.Errorf("%v: %w", e, ctx.Err())
				case <-ticker.C:
				}
			}
		} else {
			return nil
		}
	}

	return err
}

// calcDelayForNextRetry calculates the delay to wait for a given retry attempt _after_ the current attempt.
func calcDelayForNextRetry(currentAttempt int, initialDelay time.Duration, maxJitter time.Duration) time.Duration {
	currentAttempt++
	delay := time.Duration(currentAttempt) * initialDelay

	var jitter time.Duration
	if maxJitter > 0 {
		jitter = time.Duration(rand.Int63n(int64(maxJitter)))
	}

	return delay + jitter
}
