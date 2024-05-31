package cache

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/cache/synchronization"
	"github.com/DataDog/attache/internal/retry"
	"github.com/hashicorp/go-metrics"
	"go.uber.org/zap"
)

const (
	delayErrorMsg = "initial delay of %v for maintainer cannot be <= 0"
)

var (
	statsdCacheMaintainerStem          = []string{"cache", "maintainer"}
	statsdCacheMaintainerExecute       = append(statsdCacheMaintainerStem, "execute")
	statsdCacheMaintainerGet           = append(statsdCacheMaintainerStem, "get")
	statsdCacheMaintainerUpdate        = append(statsdCacheMaintainerStem, "update")
	statsdCacheMaintainerScheduled     = append(statsdCacheMaintainerStem, "scheduled")
	statsdCacheMaintainerExpirationTTL = append(statsdCacheMaintainerStem, "expiration", "ttl")
	statsdCacheMaintainerNextRefresh   = append(statsdCacheMaintainerStem, "refresh", "ttl")
	statsdCacheMaintainerState         = append(statsdCacheMaintainerStem, "state")
	statsdCacheMaintainerExpired       = append(statsdCacheMaintainerStem, "expired")
	statsdCacheMaintainerRunning       = metrics.Label{Name: "state", Value: "running"}
	statsdCacheMaintainerStopped       = metrics.Label{Name: "state", Value: "stopped"}
	statsdCacheMaintainerInit          = metrics.Label{Name: "state", Value: "init"}
	cacheHit                           = metrics.Label{Name: "cache", Value: "hit"}
	cacheMiss                          = metrics.Label{Name: "cache", Value: "miss"}
	cacheError                         = metrics.Label{Name: "cache", Value: "error"}
	cacheFalse                         = metrics.Label{Name: "cache", Value: "false"}
	statusFailed                       = metrics.Label{Name: "status", Value: "failed"}
	statusSuccess                      = metrics.Label{Name: "status", Value: "success"}
)

// Maintainer is a Refresh-Ahead Cache used to ensure that a ExpiringValue is kept valid for a given RefreshAtFunc.
// Any call to execute must be done under the syncLock to ensure there is no concurrent calls to the provider
type Maintainer[T any] struct {
	config[T]     //nolint:unused,nolintlint
	fetcher       Fetcher[T]
	refreshAtFunc RefreshAtFunc

	cachedValue cachedValue[T] //nolint:unused,nolintlint

	// Used to lock updates to all attributes of the maintainer except
	// isClosed
	syncLock synchronization.CancellableLock
	// locks updates to isClosed
	isClosedLock        sync.Mutex
	refreshAt           time.Time
	isMaintaining       bool
	isClosed            bool
	maintainerCtx       context.Context
	maintainerCtxCancel context.CancelFunc
	wg                  sync.WaitGroup

	metricsReporter metricsReporter
}

func NewMaintainer[T any](fetcher Fetcher[T], refreshAtFunc RefreshAtFunc, options ...option) *Maintainer[T] {
	m := &Maintainer[T]{
		fetcher:       fetcher,
		refreshAtFunc: refreshAtFunc,
		syncLock:      *synchronization.NewCancellableLock(),
	}
	for _, opt := range options {
		opt(&m.config)
	}

	if log := m.log; log != nil {
		m.log = log.With(zap.String("fetcher", fetcher.String()))
		m.retryOpts = append(m.retryOpts, retry.Logger(log))
	} else {
		m.log = zap.NewNop()
	}
	if m.metricSink == nil {
		m.metricSink = &metrics.BlackholeSink{}
	}
	// Default retry delay after expiration to 10s
	if m.retryAfterExpirationDelay <= 0 {
		m.retryAfterExpirationDelay = 10 * time.Second
	}

	// Creates a context tied to the maintainer lifecycle.
	// It is used to track both metrics reporting and renewal loop
	m.maintainerCtx, m.maintainerCtxCancel = context.WithCancel(context.Background())

	// start a background routine tied to the maintainer's context to update TTL metrics
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.metricsReporter.run(m.maintainerCtx, m.metricSink, m.tags())
	}()

	return m
}

func (m *Maintainer[T]) IsClosed() bool {
	m.isClosedLock.Lock()
	defer m.isClosedLock.Unlock()
	return m.isClosed
}

func (m *Maintainer[T]) Close() {
	m.isClosedLock.Lock()
	defer m.isClosedLock.Unlock()
	if m.isClosed {
		return
	}
	m.maintainerCtxCancel()
	m.wg.Wait()
	// ignore returned error: https://github.com/uber-go/zap/issues/328
	_ = m.log.Sync()
	m.isClosed = true
}

func isNil[T any](t T) bool {
	tType := reflect.TypeOf(t)
	if tType == nil {
		return true
	}
	switch tType.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Slice:
		return reflect.ValueOf(t).IsNil()
	}
	return false
}

// Get returns the ExpiringValue returned by Fetcher until the ExpiringValue expires.
func (m *Maintainer[T]) Get(ctx context.Context) (T, error) {
	if val, ok := m.cachedValue.getValue(); ok && !isNil(val) {
		m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerGet, 1.0, append(m.tags(), cacheHit))
		return val, nil
	}

	// Attempts to syncLock the maintainer, returns if the context is cancelled first
	err := m.syncLock.LockIfNotCancelled(ctx)
	if err != nil {
		var empty T
		return empty, err
	}
	defer m.syncLock.Unlock()

	// check if the value has been cached between syncLock waiting and syncLock acquisition
	if val, ok := m.cachedValue.getValue(); ok && !isNil(val) {
		m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerGet, 1.0, append(m.tags(), cacheHit))
		return val, nil
	}

	// execute directly when `Get` is called to defer to the client (aws sdk, vault, etc)'s
	// preferences for retry policies
	s, err := m.execute(ctx)
	if err != nil {
		m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerGet, 1.0, append(m.tags(), cacheError))
		if m.errorHandler != nil {
			m.errorHandler(err)
		}
		var empty T
		return empty, err
	}

	// on success, start a background refresh loop
	if !m.isMaintaining && s.ExpiresAt != (time.Time{}) {
		delay := time.Until(m.refreshAt)
		if delay <= 0 {
			m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerGet, 1.0, append(m.tags(), cacheError))
			var empty T
			return empty, fmt.Errorf(delayErrorMsg, delay)
		}

		// uses the main maintainer context -- the one passed in as an argument to Get is tied
		// to the caller's request context, we don't want to tie our background to that
		m.schedule(m.maintainerCtx, delay)
	}

	m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerGet, 1.0, append(m.tags(), cacheMiss))
	return s.Value, nil
}

func (m *Maintainer[T]) updateCacheValue(value *ExpiringValue[T]) {
	m.log.Debug("Updating cached value", zap.Time("expiration", value.ExpiresAt))
	m.cachedValue.updateValue(value)
	m.metricsReporter.setExpiresAt(value.ExpiresAt)
	m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerUpdate, 1.0, m.tags())
	if m.updateHandler != nil {
		// Passes the value by copy to ensure times are not altered.
		m.updateHandler(value.Value)
	}
}

func (m *Maintainer[T]) schedule(ctx context.Context, delay time.Duration) {
	tags := m.tags()

	m.log.Debug("scheduling value refresh", zap.Duration("delay", delay))
	m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerScheduled, 1.0, tags)

	m.isMaintaining = true
	m.metricsReporter.setMaintaining(true)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			m.syncLock.Lock()
			m.isMaintaining = false
			m.syncLock.Unlock()
			m.metricsReporter.setMaintaining(false)
		}()

		ticker := time.NewTicker(delay)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				m.log.Info("Schedule loop has been cancelled, exiting")
				return
			case <-ticker.C:
				err := retry.Do(ctx, func() error {
					err := m.syncLock.LockIfNotCancelled(ctx)
					if err != nil {
						// The context was cancelled, there is no point in running the loop
						return err
					}
					defer m.syncLock.Unlock()

					// cachedValue was already refreshed by Get(context.Context)
					if time.Now().Before(m.refreshAt) {
						return nil
					}

					_, err = m.execute(ctx)
					if err != nil {
						return err
					}

					return nil
				}, m.retryOpts...)

				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					m.log.Warn("Failed to refresh the value", zap.Error(err))
					if m.errorHandler != nil {
						m.errorHandler(err)
					}
				}

				// m.refreshAt is protected only under this syncLock
				lockErr := m.syncLock.LockIfNotCancelled(ctx)
				if lockErr != nil {
					m.log.Info("Schedule loop has been cancelled, exiting")
					return
				}
				// Get a constant vision of now to avoid edge cases here
				now := time.Now()

				expiresAt := m.cachedValue.expiresAt()
				if expiresAt.Before(now) {
					// we were unable to get a credential before our current one expired.
					// switch to a linear retry to avoid hammering the provider on recovery while allowing for a fast enough recovery.
					m.refreshAt = now.Add(m.retryAfterExpirationDelay)
					m.log.Warn("new value could not be retrieved before value expiration, refresh has been rescheduled", zap.Time("refreshAt", m.refreshAt))
					m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerExpired, 1.0, append(m.tags(), cacheError))
				} else if m.refreshAt.Before(now) {
					m.refreshAt = m.refreshAtFunc(now, expiresAt)
					if m.refreshAt.Before(now) {
						// User method is returning a refresh time in the past, switch to linear maintaining and raise an error
						m.refreshAt = now.Add(m.retryAfterExpirationDelay)
						m.log.Error("computed refreshAt time is still in the past, refresh has been rescheduled", zap.Time("refreshAt", m.refreshAt))
						m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerUpdate, 1.0, append(m.tags(), cacheError))
					}
					m.log.Warn("new value could not be retrieved before initial refresh deadline, refresh has been rescheduled", zap.Time("refreshAt", m.refreshAt))
				}

				m.metricsReporter.setRefreshAt(m.refreshAt)
				delay := time.Until(m.refreshAt)
				m.log.Debug("scheduling value refresh", zap.Duration("delay", delay))
				ticker.Reset(delay)
				m.syncLock.Unlock()

				m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerScheduled, 1.0, tags)
			}
		}
	}()
}

func (m *Maintainer[T]) execute(ctx context.Context) (*ExpiringValue[T], error) {
	timeNow := time.Now()
	value, err := m.fetcher.Fetch(ctx)
	if err != nil {
		m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerExecute, 1.0, append(m.tags(), statusFailed))

		return nil, err
	}
	m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerExecute, 1.0, append(m.tags(), statusSuccess))

	if value == nil {
		return nil, errors.New("fetcher returned a nil value and nil error")
	}

	// Do not cache value or set refreshAt if ExpiresAt is empty.
	//
	// If the Maintainer is refreshing cached credentials, let the Maintainer continue
	// trying to refresh what was previously cached (using retryAfterExpirationDelay).
	if value.ExpiresAt == (time.Time{}) {
		m.metricSink.IncrCounterWithLabels(statsdCacheMaintainerUpdate, 1.0, append(m.tags(), cacheFalse))
		return value, nil
	}

	m.updateCacheValue(value)
	m.refreshAt = m.refreshAtFunc(timeNow, value.ExpiresAt)
	m.metricsReporter.setRefreshAt(m.refreshAt)
	return value, nil
}

// tags returns a new slice containing metrics tags related to the current maintainer's operations
func (m *Maintainer[T]) tags() []metrics.Label {
	return []metrics.Label{{Name: "fetcher", Value: m.fetcher.String()}}
}

type Fetcher[T any] interface {
	// Stringer interface for returning a unique identifier
	fmt.Stringer

	// Fetch returns a valid ExpiringValue
	Fetch(ctx context.Context) (*ExpiringValue[T], error)
}

// RefreshAtFunc returns the time.Time to re-fetch the ExpiringValue. This returned time.Time should never be
// in the past.
type RefreshAtFunc func(notBefore time.Time, notAfter time.Time) time.Time

// NewPercentageRemainingRefreshAt is a basic RefreshAtFunc for calculating the time.Time at which to
// fetch a ExpiringValue based on the remaining percentage of the lifetime of a ExpiringValue.
//
// renewAfterPercentage is the percentage of time remaining at which point a ExpiringValue should be re-fetched.
// jitterPercentage is the maximum percentage of (notAfter.Sub(notBefore) * renewAfterPercentage)  to use for calculating a jitter value.
//
// i.e. if notBefore and notAfter are 60s apart, renewAfterPercentage is 0.33, and jitter percentage is 10%,
// the non jittered time will be 60s * 0.33, or 20s from now, with an added jitter of 0-2 (20s * 10%) seconds, for a
// final return value evenly spaced between 20 and 22 seconds from now.
func NewPercentageRemainingRefreshAt(renewAfterPercentage float64, jitterPercentage float64) RefreshAtFunc {
	return func(notBefore time.Time, notAfter time.Time) time.Time {
		duration := notAfter.Sub(notBefore)

		renewAt := duration.Seconds() * renewAfterPercentage
		jitter := (duration.Seconds() - renewAt) * jitterPercentage * rand.Float64()

		return notBefore.Add(time.Duration((renewAt + jitter) * float64(time.Second)))
	}
}
