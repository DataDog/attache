package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

const (
	path       = "path"
	method     = "method"
	statusCode = "statusCode"
	userAgent  = "userAgent"
)

var (
	statsdHTTPRequestRateLimited = []string{"http", "rate_limited"}
)

// Server struct for an HTTP server.
type Server struct {
	log             *zap.Logger
	gracefulTimeout time.Duration
	srv             *http.Server
	rateLimiter     *rate.Limiter
}

// Config struct for configuring a Server.
type Config struct {
	// BindAddress that the server binds to
	BindAddress string `yaml:"bind_address"`

	// GracefulTimeout duration for which the server gracefully wait for
	// existing connections to finish before exiting.
	GracefulTimeout time.Duration `yaml:"graceful_timeout"`

	// RateLimit specifies requests per second and burst with the format
	// '<reqs/sec>:<burst>'. Empty string means no limit.
	RateLimit string `yaml:"rate_limit"`
}

// Validate a Config.
func (c *Config) Validate() error {
	var result error
	if strings.TrimSpace(c.BindAddress) == "" {
		result = multierror.Append(result, errors.New("bind address cannot be empty"))
	}

	if c.GracefulTimeout == 0 {
		result = multierror.Append(result, errors.New("graceful timeout must be greater than 0"))
	}

	if c.RateLimit != "" {
		_, _, err := parseRate(c.RateLimit)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}

// NewServer creates a new Server.
func NewServer(log *zap.Logger, config Config, router *muxt.Router, opts ...Option) *Server {
	srvConfig := newServerConfig()
	for _, fn := range opts {
		fn(srvConfig)
	}

	log = log.With(zap.String("address", config.BindAddress))
	router.Use(recovery(log))
	router.Use(logMiddleware(log, srvConfig))

	if config.RateLimit != "" {
		reqs, burst, _ := parseRate(config.RateLimit)
		limiter := rate.NewLimiter(rate.Limit(reqs), burst)

		labels := []metrics.Label{{Name: "addr", Value: config.BindAddress}}
		router.Use(rateLimiterMiddleware(limiter, srvConfig.metricSink, labels))
	}

	srv := &http.Server{
		Addr:         config.BindAddress,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}

	return &Server{
		log:             log,
		gracefulTimeout: config.GracefulTimeout,
		srv:             srv,
	}
}

// Run starts the server in a goroutine, and any errors returned by the server
// at shutdown time will be passed to the provided chan parameter. Run
// returns a shutdown callback that will safely stop the server when called.
func (s *Server) Run(errs chan error) func() {
	s.log.Info("server starting")
	go func() {
		if err := s.srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("error running http server", zap.Error(err))
			errs <- err
		}
	}()

	return s.shutdown
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), s.gracefulTimeout)
	defer cancel()

	s.log.Info("server stopping")
	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Error("error while shutting down", zap.Error(err))

		return
	}

	s.log.Info("server stopped")
}

type serverConfig struct {
	ignoreRequest func(*http.Request) bool
	metricSink    metrics.MetricSink
}

func newServerConfig() *serverConfig {
	return &serverConfig{
		ignoreRequest: func(request *http.Request) bool { return false },
		metricSink:    &metrics.BlackholeSink{},
	}
}

type Option func(*serverConfig)

func WithIgnoreLoggingRequest(f func(*http.Request) bool) Option {
	return func(config *serverConfig) {
		config.ignoreRequest = f
	}
}

func WithMetricSink(metricSink metrics.MetricSink) Option {
	return func(config *serverConfig) {
		config.metricSink = metricSink
	}
}

func logMiddleware(log *zap.Logger, cfg *serverConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//Sanitize out whitespace before logging
			//Failure to do this could allow users to generate false log lines through their user agent
			requestUserAgent := r.UserAgent()
			requestUserAgent = strings.ReplaceAll(requestUserAgent, "\n", "")
			requestUserAgent = strings.ReplaceAll(requestUserAgent, "\r", "")
			if !cfg.ignoreRequest(r) {
				log.Info("request", zap.String(path, r.RequestURI), zap.String(method, r.Method), zap.String(userAgent, requestUserAgent))
			}

			wrappedW := &logMiddlewareHTTPResponseWriter{ResponseWriter: w}
			next.ServeHTTP(wrappedW, r)

			if !cfg.ignoreRequest(r) {
				log.Info("response", zap.String(path, r.RequestURI), zap.String(method, r.Method), zap.Int(statusCode, wrappedW.statusCode), zap.String(userAgent, requestUserAgent))
			}
		})
	}
}

type logMiddlewareHTTPResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *logMiddlewareHTTPResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *logMiddlewareHTTPResponseWriter) Write(byt []byte) (int, error) {
	// write (& record) status line & headers if not previous done
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(byt)
}

func recovery(log *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rc := recover(); rc != nil {
					log.Error("handler panic", zap.Any("panic", rc))

					w.WriteHeader(http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

func rateLimiterMiddleware(rateLimiter *rate.Limiter, metricSink metrics.MetricSink, labels []metrics.Label) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rateLimiter.Allow() {
				w.WriteHeader(http.StatusTooManyRequests)
				metricSink.IncrCounterWithLabels(statsdHTTPRequestRateLimited, 1.0, append([]metrics.Label{{Name: "path", Value: r.RequestURI}}, labels...))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func parseRate(rateStr string) (float64, int, error) {
	reqsStr, burstStr, found := strings.Cut(rateStr, ":")
	if !found {
		return 0, 0, errors.New("rate limit must be in the format '<reqs/sec>:<busrt>'")
	}

	req, reqErr := strconv.ParseFloat(reqsStr, 64)
	burst, burstErr := strconv.Atoi(burstStr)
	if reqErr != nil || burstErr != nil {
		return 0, 0, errors.New("rate limit must be in the format '<reqs/sec>:<burst>'")
	}

	return req, burst, nil
}
