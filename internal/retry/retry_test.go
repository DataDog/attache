package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func Test_calcDelayForNextRetry(t *testing.T) {
	type args struct {
		attempt      int
		initialDelay time.Duration
		maxJitter    time.Duration
	}
	tests := map[string]struct {
		args args
		want time.Duration
	}{
		"attempt 0 (initial attempt)": {
			args: args{
				attempt:      0,
				initialDelay: 3 * time.Second,
				maxJitter:    0,
			},
			want: 3 * time.Second,
		},
		"attempt 1": {
			args: args{
				attempt:      1,
				initialDelay: 3 * time.Second,
				maxJitter:    0,
			},
			want: 6 * time.Second,
		},
		"attempt 2": {
			args: args{
				attempt:      2,
				initialDelay: 3 * time.Second,
				maxJitter:    0,
			},
			want: 9 * time.Second,
		},
		"attempt 3": {
			args: args{
				attempt:      3,
				initialDelay: 3 * time.Second,
				maxJitter:    0,
			},
			want: 12 * time.Second,
		},
		"attempt 4": {
			args: args{
				attempt:      4,
				initialDelay: 3 * time.Second,
				maxJitter:    0,
			},
			want: 15 * time.Second,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			got := calcDelayForNextRetry(tt.args.attempt, tt.args.initialDelay, tt.args.maxJitter)
			if got != tt.want {
				t.Errorf("calcRetryDelay() got1 = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_calcRetryDelayWithJitter(t *testing.T) {
	got := calcDelayForNextRetry(0, 1*time.Second, 1*time.Second)
	assert.GreaterOrEqual(t, got, 1*time.Second)
	assert.LessOrEqual(t, got, 2*time.Second)
}

func TestMaxAttempts(t *testing.T) {
	tests := map[string]struct {
		maxAttempts int
		want        *Config
	}{
		"success": {
			maxAttempts: 2,
			want: &Config{
				maxAttempts: 2,
			},
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			f := MaxAttempts(tt.maxAttempts)
			c := &Config{}
			f(c)
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestInitialDelay(t *testing.T) {
	tests := map[string]struct {
		initialDelay time.Duration
		want         *Config
	}{
		"success": {
			initialDelay: 2 * time.Minute,
			want: &Config{
				initialDelay: 2 * time.Minute,
			},
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			f := InitialDelay(tt.initialDelay)
			c := &Config{}
			f(c)
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestLogger(t *testing.T) {
	tests := map[string]struct {
		logger *zap.Logger
		want   *Config
	}{
		"success": {
			logger: zap.NewNop(),
			want: &Config{
				logger: zap.NewNop(),
			},
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			f := Logger(tt.logger)
			c := &Config{}
			f(c)
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestMaxJitter(t *testing.T) {
	tests := map[string]struct {
		maxJitter time.Duration
		want      *Config
	}{
		"success": {
			maxJitter: 1 * time.Second,
			want: &Config{
				maxJitter: 1 * time.Second,
			},
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			f := MaxJitter(tt.maxJitter)
			c := &Config{}
			f(c)
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestDo(t *testing.T) {
	tests := map[string]struct {
		retryable RetryableFunc
		opts      []Option
		wantErr   error
	}{
		"success": {
			retryable: func() RetryableFunc {
				m := &mockRetryable{}
				m.On("execute").Return(nil)

				return m.execute
			}(),
			opts:    []Option{MaxAttempts(3), MaxJitter(0)},
			wantErr: nil,
		},
		"error on all retry": {
			retryable: func() RetryableFunc {
				m := &mockRetryable{}
				m.On("execute").Return(errors.New("failing")).Times(3)

				return m.execute
			}(),
			opts:    []Option{MaxAttempts(3), MaxJitter(0)},
			wantErr: errors.New("failing"),
		},
		"success after error": {
			retryable: func() RetryableFunc {
				m := &mockRetryable{}
				m.On("execute").Return(errors.New("failing")).Times(2)
				m.On("execute").Return(nil)

				return m.execute
			}(),
			opts:    []Option{MaxAttempts(3), MaxJitter(0)},
			wantErr: nil,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			err := Do(context.TODO(), tt.retryable, tt.opts...)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

type mockRetryable struct {
	mock.Mock
}

func (m *mockRetryable) execute() error {
	args := m.Called()

	return args.Error(0)
}
