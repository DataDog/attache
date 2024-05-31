package imds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-metrics"
	"go.uber.org/zap"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

var (
	statsdCloudCredRequest = []string{"cloudcred", "request"}

	labelVaultMethod = metrics.Label{Name: "method", Value: "vault"}
	labelSuccess     = metrics.Label{Name: "status", Value: "success"}
	labelFail        = metrics.Label{Name: "status", Value: "fail"}
)

// Provider encapsulates all the parameters necessary for implementing the cloud
// provider's Metadata Service backed by Vault.
type Provider interface {

	// Name returns the name of the Provider.
	Name() string

	// RegisterHandlers registers HTTP handlers with the server.
	//
	// `mux.Router` parameter is the server and `HandlerFactory` is a factory
	// for creating HTTP Handlers for handling requests.
	RegisterHandlers(router *muxt.Router, factory *HandlerFactory) error
}

var _ handlerError = &roleDoesNotExistError{}

type roleDoesNotExistError struct {
	roleName string
}

func (err *roleDoesNotExistError) Error() string {
	return fmt.Sprintf("role %q does not exist", err.roleName)
}

func (err *roleDoesNotExistError) Status() int {
	return 404
}

func newRoleDoesNotExistError(roleName string) error {
	return &roleDoesNotExistError{
		roleName: roleName,
	}
}

// HandlerFactory struct for creating Handlers.
type HandlerFactory struct {
	logger     *zap.Logger
	metricSink metrics.MetricSink
}

// NewHandlerFactory creates a HandlerFactory.
func NewHandlerFactory(metricSink metrics.MetricSink, log *zap.Logger) *HandlerFactory {
	return &HandlerFactory{
		logger:     log,
		metricSink: metricSink,
	}
}

// CreateHTTPHandler for an HTTP server.
func (f *HandlerFactory) CreateHTTPHandler(provider string, handlerFunc handlerFunc) http.Handler {
	return &handler{
		function:   handlerFunc,
		logger:     f.logger,
		name:       functionName(handlerFunc),
		provider:   provider,
		metricSink: f.metricSink,
	}
}

func functionName(handlerFunc handlerFunc) string {
	dotName := runtime.FuncForPC(reflect.ValueOf(handlerFunc).Pointer()).Name()
	n := strings.Split(dotName, ".")
	name := strings.TrimSuffix(n[len(n)-1], "-fm")

	return name
}

type handlerError interface {
	error
	Status() int
}

// HTTPError should be returned for all HTTP handlers that need to return an error with a custom
// HTTP status code or http response body. Otherwise, HTTP handlers should return `error`.
type HTTPError struct {
	code  int
	error error
}

func (he HTTPError) Error() string {
	return he.error.Error()
}

// Status code of the HTTP response.
func (he HTTPError) Status() int {
	return he.code
}

type handlerFunc func(*zap.Logger, http.ResponseWriter, *http.Request) error

type handler struct {
	function   handlerFunc
	logger     *zap.Logger
	name       string
	metricSink metrics.MetricSink
	provider   string
}

var requestTagsKey = &struct{}{}

func wrapRequestTag(r *http.Request, k, v string) *http.Request {
	tags, ok := r.Context().Value(requestTagsKey).(map[string]string)
	if ok && tags != nil {
		tags[k] = v
		return r
	}

	tags = map[string]string{k: v}

	return r.WithContext(context.WithValue(r.Context(), requestTagsKey, tags))
}

func (h *handler) requestTags(w *responseWriter, r *http.Request) []metrics.Label {
	extra, _ := r.Context().Value(requestTagsKey).(map[string]string)

	tags := make([]metrics.Label, 4, 4+len(extra))

	tags = append(tags,
		metrics.Label{Name: "method:%v", Value: r.Method},
		metrics.Label{Name: "name:%v", Value: h.name},
		metrics.Label{Name: "provider:%v", Value: h.provider},
		metrics.Label{Name: "status_code:%v", Value: strconv.Itoa(w.statusCode)},
	)

	for k, v := range extra {
		tags = append(tags, metrics.Label{Name: k, Value: v})
	}

	return tags
}

const (
	statusClientClosedRequest     = 499
	statusClientClosedRequestText = "Client Closed Request"
)

// ServeHTTP serves HTTP requests.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := newResponseWriter(w)
	start := timeNow()

	err := h.function(h.logger, rw, r)
	if err != nil {
		var handlerError handlerError
		if errors.As(err, &handlerError) {
			// always log the full original error, but take the status from the underlying wrapped
			// httpError, and return the error message and status from the underlying http error only.
			h.logger.Error(http.StatusText(handlerError.Status()), zap.Error(err))
			http.Error(rw, handlerError.Error(), handlerError.Status())
		} else if errors.Is(err, context.Canceled) {
			// use non-standard 499 status code for instrumentation. This should be unseen by the client.
			h.logger.Warn(statusClientClosedRequestText, zap.Error(err))
			http.Error(rw, statusClientClosedRequestText, statusClientClosedRequest)
		} else {
			h.logger.Error(http.StatusText(http.StatusInternalServerError), zap.Error(err))
			http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	tags := h.requestTags(rw, r)

	h.metricSink.AddSampleWithLabels([]string{"request_duration_seconds"}, float32(time.Since(start).Seconds()), tags)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader for HTTP responses.
func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}
