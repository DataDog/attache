package cache

import (
	"time"

	"github.com/DataDog/attache/internal/retry"
	"github.com/hashicorp/go-metrics"
	"go.uber.org/zap"
)

// CacheUpdateHandler is called every time the cached value is updated if requested as an option
// The value provided is the ExpiringValue construct which is itself containing the value within the cache
// The handler must not modify the value provided
type CacheUpdateHandler[T any] func(T)

// ErrorHandler is called every time an error is returned when attempting to update the cached value
type ErrorHandler func(error)

// Go generics are currently limited when using functions.
// This prevents passing Options potentially referring to the type without having all options typed.
// To avoid pushing this cumbersome syntax on users (e.g. having to write WithLogger[T]),
// we abstract it here, knowing that all those are internal types and the user only deals with the main calls.
type optionConfig interface {
	setLogger(*zap.Logger)
	setMetricsSink(metrics.MetricSink)
	setRetryOptions([]retry.Option)
	setRetryAfterExpirarionDelay(time.Duration)
	setErrorHandler(ErrorHandler)
}

type typedOptionConfig[T any] interface {
	setUpdateHandler(CacheUpdateHandler[T])
}

type config[T any] struct {
	retryOpts                 []retry.Option
	retryAfterExpirationDelay time.Duration
	log                       *zap.Logger
	metricSink                metrics.MetricSink
	errorHandler              ErrorHandler
	updateHandler             CacheUpdateHandler[T] //nolint:unused,nolintlint
}

var _ typedOptionConfig[string] = &config[string]{}

func (c *config[T]) setLogger(log *zap.Logger) {
	c.log = log
}

func (c *config[T]) setMetricsSink(metricSink metrics.MetricSink) {
	c.metricSink = metricSink
}

func (c *config[T]) setRetryOptions(retryOpts []retry.Option) {
	c.retryOpts = retryOpts
}

func (c *config[T]) setRetryAfterExpirarionDelay(delay time.Duration) {
	c.retryAfterExpirationDelay = delay
}

func (c *config[T]) setErrorHandler(errorHandler ErrorHandler) {
	c.errorHandler = errorHandler
}

//lint:ignore U1000 linters are having a hard time with generics
func (c *config[T]) setUpdateHandler(updateHandler CacheUpdateHandler[T]) {
	c.updateHandler = updateHandler
}

type option func(interface{})

func WithRetryOptions(retryOpts []retry.Option) option {
	return func(param interface{}) {
		if c, ok := param.(optionConfig); ok {
			c.setRetryOptions(retryOpts)
		}
	}
}

// If a value is not renewed prior to its expiration, the maintainer uses a linear retry with a default delay of 10s.
// WithRetryAfterExpirarionDelay sets this delay to another value if desired by the user.
// Decreasing the delay does speedup recovery once the provider is available, but also increases the impact of the provider on recovery.
func WithRetryAfterExpirarionDelay(delay time.Duration) option {
	return func(param interface{}) {
		if c, ok := param.(optionConfig); ok {
			c.setRetryAfterExpirarionDelay(delay)
		}
	}
}

func WithLogger(log *zap.Logger) option {
	return func(param interface{}) {
		if c, ok := param.(optionConfig); ok {
			c.setLogger(log)
		}
	}
}

func WithMetricsSink(sink metrics.MetricSink) option {
	return func(param interface{}) {
		if c, ok := param.(optionConfig); ok {
			c.setMetricsSink(sink)
		}
	}
}

func WithCacheUpdateHandler[T any](updateHandler CacheUpdateHandler[T]) option {
	return func(param interface{}) {
		if c, ok := param.(typedOptionConfig[T]); ok {
			c.setUpdateHandler(updateHandler)
		}
	}
}

func WithErrorHandler(errorHandler ErrorHandler) option {
	return func(param interface{}) {
		if c, ok := param.(optionConfig); ok {
			c.setErrorHandler(errorHandler)
		}
	}
}
