package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_middleware_recovery(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) { panic("test panic") }

	req := httptest.NewRequest("GET", "http://localhost/panic", nil)

	w := httptest.NewRecorder()

	assert.Panics(t, func() {
		http.HandlerFunc(fn).ServeHTTP(w, req)
	}, "panic handler panics")

	assert.NotPanics(t, func() {
		recovery(zap.NewNop())(http.HandlerFunc(fn)).ServeHTTP(w, req)
	}, "recovery handler does not panic")

	resp := w.Result()
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func Test_logMiddleware(t *testing.T) {
	tests := map[string]struct {
		cfg        *serverConfig
		hdlr       http.HandlerFunc
		wantStatus int
		assertLogs func(*testing.T, *observer.ObservedLogs)
	}{
		"log request": {
			cfg: &serverConfig{
				ignoreRequest: func(request *http.Request) bool { return false },
			},
			hdlr:       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
			wantStatus: http.StatusNoContent,
			assertLogs: func(t *testing.T, logs *observer.ObservedLogs) {
				t.Helper()
				assert.Equal(t, 2, logs.Len())
				assert.Equal(t, 1, logs.FilterField(zap.Int(statusCode, http.StatusNoContent)).Len())
			},
		},
		"log request with implicit writeheader": {
			cfg: &serverConfig{
				ignoreRequest: func(request *http.Request) bool { return false },
			},
			hdlr:       func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte{}) },
			wantStatus: http.StatusOK,
			assertLogs: func(t *testing.T, logs *observer.ObservedLogs) {
				t.Helper()
				assert.Equal(t, 2, logs.Len())
				assert.Equal(t, 1, logs.FilterField(zap.Int(statusCode, http.StatusOK)).Len())
			},
		},
		"skip log request": {
			cfg: &serverConfig{
				ignoreRequest: func(request *http.Request) bool { return true },
			},
			hdlr:       func(w http.ResponseWriter, r *http.Request) {},
			wantStatus: http.StatusOK,
			assertLogs: func(t *testing.T, logs *observer.ObservedLogs) {
				t.Helper()
				assert.Equal(t, 0, logs.Len())
			},
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost/test", nil)
			w := httptest.NewRecorder()

			core, recorded := observer.New(zapcore.InfoLevel)
			logger := zap.New(core)

			logMiddleware(logger, tt.cfg)(tt.hdlr).ServeHTTP(w, req)
			resp := w.Result()
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			tt.assertLogs(t, recorded)
		})
	}
}

func Test_parseRate(t *testing.T) {
	tests := map[string]struct {
		rateLimit string
		assert    func(t *testing.T, rate float64, burst int, err error)
	}{
		"valid rate": {
			rateLimit: "20:100",
			assert: func(t *testing.T, rate float64, burst int, err error) {
				t.Helper()
				assert.NoError(t, err)
				assert.Equal(t, float64(20), rate)
				assert.Equal(t, 100, burst)
			},
		},
		"bad burst": {
			rateLimit: "20:bad",
			assert: func(t *testing.T, rate float64, burst int, err error) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		"bad rate": {
			rateLimit: "bad:100",
			assert: func(t *testing.T, rate float64, burst int, err error) {
				t.Helper()
				assert.Error(t, err)
			},
		},
		"no colon": {
			rateLimit: "12345",
			assert: func(t *testing.T, rate float64, burst int, err error) {
				t.Helper()
				assert.Error(t, err)
			},
		},
	}

	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			rate, burst, err := parseRate(tt.rateLimit)
			tt.assert(t, rate, burst, err)
		})
	}
}
