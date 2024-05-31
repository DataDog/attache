package cache

import (
	"context"
	"errors"
	"math"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/attache/internal/retry"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func Test_NewPercentageRemainingRefreshAt(t *testing.T) {
	type fields struct {
		renewAtPercentage float64
		jitterPercentage  float64
	}

	tests := map[string]struct {
		fields    fields
		notBefore time.Time
		notAfter  time.Time
		want      time.Time
		within    time.Duration
	}{
		"no jitter": {
			fields: fields{
				renewAtPercentage: 0.25,
				jitterPercentage:  0,
			},
			notBefore: time.Date(2021, 8, 1, 11, 0, 0, 0, time.Local),
			notAfter:  time.Date(2021, 8, 1, 12, 0, 0, 0, time.Local),
			want:      time.Date(2021, 8, 1, 11, 15, 0, 0, time.Local),
			within:    0,
		},
		"actual-notBefore result in 0": {
			fields: fields{
				renewAtPercentage: 0.0001,
				jitterPercentage:  0,
			},
			notBefore: time.Date(2021, 8, 1, 11, 0, 0, 0, time.Local),
			notAfter:  time.Date(2021, 8, 1, 12, 0, 0, 0, time.Local),
			want:      time.Date(2021, 8, 1, 11, 0, 0, 360*int(time.Millisecond), time.Local),
			within:    0,
		},
		"jitter": {
			fields: fields{
				renewAtPercentage: 0.8,
				jitterPercentage:  0.01,
			},
			notBefore: time.Date(2021, 8, 1, 11, 0, 0, 0, time.Local),
			notAfter:  time.Date(2021, 8, 1, 12, 0, 0, 0, time.Local),
			want:      time.Date(2021, 8, 1, 11, 48, 0, 0, time.Local),
			within:    time.Duration((12*time.Minute).Seconds()*0.01) * time.Second,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			p := NewPercentageRemainingRefreshAt(tt.fields.renewAtPercentage, tt.fields.jitterPercentage)
			got := p(tt.notBefore, tt.notAfter)
			assertDuration(t, tt.want, got, tt.within)
		})
	}
}

func assertDuration(t *testing.T, expected time.Time, actual time.Time, delta time.Duration) {
	t.Helper()

	if math.Abs(expected.Sub(actual).Seconds()) > delta.Seconds() {
		assert.Failf(t, "duration not within range", "expected duration %s is not within %s of actual duration %s", expected, delta, actual)
	}
}

func TestMaintainer_Get_Successful(t *testing.T) {
	t.Run("no update handler", func(t *testing.T) {
		mockedMaintainer := NewMaintainer[string](
			newReplayFetcher([]replayResponse[string]{
				{value: newMockExpiringValue(), err: nil},
			}...),
			newFetchAfter(1*time.Minute),
			WithLogger(zaptest.NewLogger(t)),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		require.NoError(t, err)
		assert.NotEmpty(t, got)

		mockedMaintainer.Close()

		fetcher := newReplayFetcher([]replayResponse[string]{
			{value: newMockExpiringValue(), err: nil},
			{value: newMockExpiringValue(), err: nil},
		}...)
		uuidMaintainer := NewMaintainer[string](fetcher, newFetchAfter(1*time.Minute), WithLogger(zaptest.NewLogger(t)))

		gotUUID, err := uuidMaintainer.Get(context.TODO())
		require.NoError(t, err)
		require.NotEmpty(t, gotUUID)

		got, err = uuidMaintainer.Get(context.TODO())
		require.NoError(t, err)
		assert.Equal(t, gotUUID, got)

		uuidMaintainer.Close()
	})

	t.Run("with update handler", func(t *testing.T) {
		updatesHandled := 0
		mockedMaintainer := NewMaintainer[string](
			newReplayFetcher([]replayResponse[string]{
				{value: newMockExpiringValue(), err: nil},
			}...),
			newFetchAfter(1*time.Minute),
			WithLogger(zaptest.NewLogger(t)),
			WithCacheUpdateHandler(func(str string) {
				updatesHandled++
				assert.NotEmpty(t, str)
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		require.NoError(t, err)
		assert.NotEmpty(t, got)
		assert.Equal(t, 1, updatesHandled)

		mockedMaintainer.Close()
	})
}

func TestMaintainer_Get_Failure(t *testing.T) {
	t.Run("get returns error on failure", func(t *testing.T) {
		mockedMaintainer := NewMaintainer[string](
			newReplayFetcher([]replayResponse[string]{
				{value: nil, err: errors.New("error fetching value")},
				{value: nil, err: errors.New("error fetching value")},
				{value: nil, err: errors.New("error fetching value")},
			}...),
			newFetchAfter(1*time.Minute),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(1),
				retry.InitialDelay(100 * time.Millisecond),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.Error(t, err)
		assert.Empty(t, got)

		mockedMaintainer.Close()
	})

	t.Run("get returns successful after failure", func(t *testing.T) {
		mockedMaintainer := NewMaintainer[string](
			newReplayFetcher([]replayResponse[string]{
				{value: nil, err: errors.New("error fetching value")},
				{value: newMockExpiringValue(), err: nil},
			}...),
			newFetchAfter(1*time.Minute),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(100 * time.Millisecond),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.Error(t, err)
		assert.Empty(t, got)

		got, err = mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)

		mockedMaintainer.Close()
	})

	t.Run("get returns failure after success", func(t *testing.T) {
		fetcher := newReplayFetcher([]replayResponse[uuid.UUID]{
			{value: &ExpiringValue[uuid.UUID]{Value: uuid.New(), ExpiresAt: time.Now()}, err: nil},
			{value: nil, err: nil},
		}...)
		mockedMaintainer := NewMaintainer[uuid.UUID](
			fetcher,
			newFetchAfter(10*time.Millisecond),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(1),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)

		<-fetcher.refreshChan

		cachedGot, err := mockedMaintainer.Get(context.TODO())
		assert.Error(t, err)
		assert.Equal(t, uuid.UUID{}, cachedGot)

		mockedMaintainer.Close()
	})
}

func TestMaintainedValue(t *testing.T) {
	t.Run("successfulRefresh", func(t *testing.T) {
		updatesHandled := int32(0)
		lastUUID := ""
		firstValue := newMockExpiringValue()
		secondValue := newMockExpiringValue()
		// Refresh only once to be able to detect it individually
		secondValue.ExpiresAt = time.Now().Add(10 * time.Second)

		fetcher := newReplayFetcher([]replayResponse[string]{
			{value: firstValue, err: nil},
			{value: secondValue, err: nil},
		}...)

		mockedMaintainer := NewMaintainer[string](
			fetcher,
			newFetchAfter(30*time.Millisecond),
			WithLogger(zaptest.NewLogger(t)),
			WithCacheUpdateHandler(func(str string) {
				atomic.AddInt32(&updatesHandled, 1)
				assert.NotEqual(t, lastUUID, str, "Got same update at call %d", updatesHandled)
				lastUUID = str
			}),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(50 * time.Millisecond),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)
		assert.EqualValues(t, 1, atomic.LoadInt32(&updatesHandled))
		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		<-fetcher.refreshChan
		time.Sleep(5 * time.Millisecond)
		assert.EqualValues(t, 2, atomic.LoadInt32(&updatesHandled))
		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		uuid, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.Equal(t, lastUUID, uuid)
		assert.EqualValues(t, 2, atomic.LoadInt32(&updatesHandled))

		mockedMaintainer.Close()
	})

	t.Run("concurrent access", func(t *testing.T) {
		firstValue := newMockExpiringValue()
		firstValue.ExpiresAt = time.Now().Add(10 * time.Second)

		fetcher := newSlowFetcher([]replayResponse[string]{
			{value: firstValue, err: nil},
		})

		// First fetch will return immediately
		// Following fetch will take long enough
		mockedMaintainer := NewMaintainer[string](
			fetcher,
			newFetchAfter(10*time.Millisecond),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(50 * time.Millisecond),
			}),
		)

		baseCtx := context.TODO()

		got, err := mockedMaintainer.Get(baseCtx)
		assert.NoError(t, err)
		assert.NotEmpty(t, got)
		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		<-fetcher.waitChan

		// At this stage the fetcher is running, so the maintainer is locked
		ctx, cancel := context.WithTimeout(baseCtx, 5*time.Millisecond)
		assert.Error(t, mockedMaintainer.syncLock.LockIfNotCancelled(ctx))
		cancel()

		// We can still access the credentials
		got, err = mockedMaintainer.Get(baseCtx)
		assert.NoError(t, err)
		assert.NotEmpty(t, got)

		mockedMaintainer.Close()
	})

	t.Run("fetch return nil value with error", func(t *testing.T) {
		errorsHandled := int32(0)
		fetcher := newReplayFetcher([]replayResponse[string]{
			{value: newMockExpiringValue(), err: nil},
			{value: nil, err: errors.New("error fetching value")},
		}...)
		mockedMaintainer := NewMaintainer[string](
			fetcher,
			newFetchAfter(10*time.Millisecond),
			WithLogger(zaptest.NewLogger(t)),
			WithErrorHandler(func(err error) {
				atomic.AddInt32(&errorsHandled, 1)
			}),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(10 * time.Millisecond),
			}),
			WithRetryAfterExpirarionDelay(10*time.Millisecond),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)
		assert.EqualValues(t, 0, atomic.LoadInt32(&errorsHandled))

		<-fetcher.refreshChan // We allow two attempts
		<-fetcher.refreshChan
		// Wait for the goroutine to call the updater
		time.Sleep(5 * time.Millisecond)
		assert.EqualValues(t, 1, atomic.LoadInt32(&errorsHandled))

		// Maintaining is still occurring as we no longer stop.
		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		select {
		case <-fetcher.refreshChan:
		case <-time.After(10 * time.Millisecond):
			assert.Fail(t, "refresh has occurred after more than 15ms")
		}
		// Two retries again
		<-fetcher.refreshChan
		// Wait for the goroutine to call the updater
		time.Sleep(5 * time.Millisecond)
		assert.EqualValues(t, 2, atomic.LoadInt32(&errorsHandled))

		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		newGot, err := mockedMaintainer.Get(context.TODO())
		assert.Error(t, err)
		assert.Empty(t, newGot)
		assert.EqualValues(t, 3, atomic.LoadInt32(&errorsHandled))

		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		mockedMaintainer.Close()
	})

	t.Run("fetch returns nil value and nil error", func(t *testing.T) {
		fetcher := newReplayFetcher([]replayResponse[string]{
			{value: newMockExpiringValue(), err: nil},
			{value: nil, err: nil},
		}...)
		mockedMaintainer := NewMaintainer[string](
			fetcher,
			newFetchAfter(1*time.Second),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(50 * time.Millisecond),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)

		<-fetcher.refreshChan

		newGot, err := mockedMaintainer.Get(context.TODO())
		assert.Error(t, err)
		assert.Empty(t, newGot)

		mockedMaintainer.Close()
	})
}

func TestRefreshAtReturnsInvalidTime(t *testing.T) {
	t.Run("ticker initialization error", func(t *testing.T) {
		mockedMaintainer := NewMaintainer[string](
			newReplayFetcher([]replayResponse[string]{
				{value: newMockExpiringValue(), err: nil},
				{value: nil, err: errors.New("error fetching value")},
			}...),
			newFetchAfter(0),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(50 * time.Millisecond),
			}),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.Regexp(t, regexp.MustCompile(`initial delay of .+ for maintainer cannot be <= 0`), err.Error())
		assert.Empty(t, got)

		mockedMaintainer.Close()
	})

	t.Run("ticker reset error after initialization", func(t *testing.T) {
		fetcher := newReplayFetcher([]replayResponse[string]{
			{value: newMockExpiringValue(), err: nil},
			{value: newMockExpiringValue(), err: nil},
			{value: newMockExpiringValue(), err: nil},
			{value: newMockExpiringValue(), err: nil},
		}...)
		mockedMaintainer := NewMaintainer[string](
			fetcher,
			func() RefreshAtFunc {
				var initialized bool

				return func(notBefore time.Time, notAfter time.Time) time.Time {
					if !initialized {
						initialized = true

						return notBefore.Add(40 * time.Millisecond)
					}

					return notBefore.Add(-1 * time.Millisecond)
				}
			}(),
			WithLogger(zaptest.NewLogger(t)),
			WithRetryOptions([]retry.Option{
				retry.MaxAttempts(2),
				retry.InitialDelay(5 * time.Millisecond),
			}),
			WithRetryAfterExpirarionDelay(20*time.Millisecond),
		)

		got, err := mockedMaintainer.Get(context.TODO())
		assert.NoError(t, err)
		assert.NotEmpty(t, got)

		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		<-fetcher.refreshChan // We allow two attempts
		<-fetcher.refreshChan
		lastRefresh := time.Now()
		// Let the goroutine the time to potentially update the value
		time.Sleep(5 * time.Millisecond)

		// Value is still being watched even though it expired
		got, ok := mockedMaintainer.cachedValue.getValue()
		assert.False(t, ok) // Value has expired
		assert.Empty(t, got)

		mockedMaintainer.syncLock.Lock()
		assert.True(t, mockedMaintainer.isMaintaining)
		mockedMaintainer.syncLock.Unlock()

		// Ensure the refresh occurred roughly after 20ms, matching the retry after expiration delay
		<-fetcher.refreshChan
		assert.WithinDuration(t, lastRefresh.Add(20*time.Millisecond), time.Now(), 3*time.Millisecond)

		mockedMaintainer.Close()
	})
}

func TestIsNil(t *testing.T) {
	var nullIntPtr *int
	assert.True(t, nullIntPtr == nil)
	two := 2
	nonNullIntPtr := &two

	for name, test := range map[string]struct {
		value  interface{}
		result bool
	}{
		"nil":           {nil, true},
		"nil value":     {nullIntPtr, true},
		"non nil value": {nonNullIntPtr, false},
		"string":        {"test", false},
		"empty string":  {"", false},
		"struct":        {struct{}{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.result, isNil(test.value))
		})
	}
}

func newFetchAfter(d time.Duration) RefreshAtFunc {
	return func(notBefore time.Time, notAfter time.Time) time.Time {
		return notBefore.Add(d)
	}
}

type replayResponse[T any] struct {
	value *ExpiringValue[T] //nolint:unused,nolintlint
	err   error
}

type replayFetcher[T any] struct {
	responses []replayResponse[T] //nolint:unused,nolintlint

	index       int
	refreshChan chan struct{}
}

func newReplayFetcher[T any](replayResponses ...replayResponse[T]) *replayFetcher[T] {
	return newReplayFetcherWithExpiresAt(replayResponses...)
}

func newReplayFetcherWithExpiresAt[T any](replayResponses ...replayResponse[T]) *replayFetcher[T] {
	return &replayFetcher[T]{
		responses:   replayResponses,
		refreshChan: make(chan struct{}, len(replayResponses)+1),
	}
}

func (m *replayFetcher[T]) String() string {
	return "replay"
}

func (m *replayFetcher[T]) Fetch(ctx context.Context) (*ExpiringValue[T], error) {
	if m.index != 0 {
		// We do notify of each subsequent refresh, but not the initial get
		m.refreshChan <- struct{}{}
	}
	response := m.responses[m.index]
	if m.index < len(m.responses)-1 {
		m.index++
	}

	return response.value, response.err
}

type slowFetcher[T any] struct {
	responses []replayResponse[T] //nolint:unused,nolintlint

	index    int
	waitChan chan struct{}
}

func newSlowFetcher[T any](replayResponse []replayResponse[T]) *slowFetcher[T] {
	return &slowFetcher[T]{
		responses: replayResponse,
		waitChan:  make(chan struct{}, len(replayResponse)+1),
	}
}

func (f *slowFetcher[T]) Fetch(ctx context.Context) (*ExpiringValue[T], error) {
	if f.index < len(f.responses) {
		resp := f.responses[f.index]
		f.index++
		return resp.value, resp.err
	}
	f.waitChan <- struct{}{}

	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *slowFetcher[T]) String() string {
	return "slow"
}

func newMockExpiringValue() *ExpiringValue[string] {
	return &ExpiringValue[string]{
		Value:     uuid.New().String(),
		ExpiresAt: time.Now().Add(10 * time.Millisecond),
	}
}
