package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/rate"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-retryablehttp"
	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	vaulttrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/hashicorp/vault"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	statsdVaultRequest          = []string{"vault", "request"}
	statsdVaultRequestHTTPRetry = []string{"vault", "request", "http", "retry"}
	rateLimitDelayed            = metrics.Label{Name: "rate_limit_action", Value: "delayed"}
	rateLimitUntouched          = metrics.Label{Name: "rate_limit_action", Value: "untouched"}
)

const (
	httpMethod     = "http_method"
	httpPath       = "http_path"
	httpStatusCode = "http_status_code"
	xVaultToken    = "X-Vault-Token"
	xVaultRequest  = "X-Vault-Request"
)

type Client struct {
	address             string
	retryableHTTPClient *retryablehttp.Client

	limiter *rate.Limiter

	// Timeout is for setting custom timeout parameter in the HttpClient
	timeout time.Duration

	token string

	modifyMutex sync.RWMutex

	metricSink metrics.MetricSink
	log        *zap.Logger
}

type Config struct {
	Address    string
	Token      string
	Insecure   bool
	MetricSink metrics.MetricSink
	Log        *zap.Logger
}

func DefaultConfig() *Config {
	var vaultAddr string
	if envVaultAddr, ok := os.LookupEnv("VAULT_ADDR"); ok {
		vaultAddr = envVaultAddr
	} else {
		vaultAddr = "https://127.0.0.1:8500"
	}

	var vaultToken string
	if envVaultToken, ok := os.LookupEnv("VAULT_TOKEN"); ok {
		vaultToken = envVaultToken
	}

	return &Config{
		Address:    vaultAddr,
		Token:      vaultToken,
		MetricSink: &metrics.BlackholeSink{},
		Log:        zap.NewNop(),
	}
}

func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	httpClient := cleanhttp.DefaultPooledClient()
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http transport %T not of type %T", httpClient.Transport, &http.Transport{})
	}

	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}

	if config.Insecure {
		clientTLSConfig := transport.TLSClientConfig
		clientTLSConfig.InsecureSkipVerify = true
	}

	httpClient = vaulttrace.WrapHTTPClient(httpClient, vaulttrace.WithAnalytics(true))

	return &Client{
		address: config.Address,
		token:   config.Token,
		retryableHTTPClient: &retryablehttp.Client{
			HTTPClient:   httpClient,
			RetryWaitMin: time.Millisecond * 1000,
			RetryWaitMax: time.Millisecond * 1500,
			RetryMax:     2,
			Backoff:      retryablehttp.LinearJitterBackoff,
			CheckRetry:   ObservedRetryPolicy(config.Log, config.MetricSink), //nolint:bodyclose
			ErrorHandler: retryablehttp.PassthroughErrorHandler,
		},
		timeout:     time.Second * 60,
		modifyMutex: sync.RWMutex{},
		metricSink:  config.MetricSink,
		log:         config.Log,
	}, nil
}

func (d *Client) SetToken(token string) {
	d.modifyMutex.Lock()
	defer d.modifyMutex.Unlock()

	d.token = token
}

func (d *Client) Token() string {
	d.modifyMutex.RLock()
	defer d.modifyMutex.RUnlock()

	return d.token
}

func (d *Client) SetLimiter(limiter *rate.Limiter) {
	d.modifyMutex.Lock()
	defer d.modifyMutex.Unlock()

	d.limiter = limiter
}

func (d *Client) Read(ctx context.Context, p string) (*vaultapi.Secret, error) {
	return d.ReadWithData(ctx, p, nil)
}

func (d *Client) ReadWithData(ctx context.Context, p string, data map[string][]string) (*vaultapi.Secret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.address+"/v1/"+p, http.NoBody)
	if err != nil {
		return nil, err
	}

	var values url.Values
	for k, v := range data {
		if values == nil {
			values = make(url.Values)
		}
		for _, val := range v {
			values.Add(k, val)
		}
	}
	req.URL.RawQuery = values.Encode()

	resp, err := d.do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := vaultapi.ParseSecret(resp.Body)
		switch parseErr { //nolint:errorlint
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (d *Client) Write(ctx context.Context, p string, data map[string]interface{}) (*vaultapi.Secret, error) {
	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, d.address+"/v1/"+p, bytes.NewReader(marshalled))
	if err != nil {
		return nil, err
	}

	resp, err := d.do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := vaultapi.ParseSecret(resp.Body)
		switch parseErr { //nolint:errorlint
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, err
		}
	}
	if err != nil {
		return nil, err
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (d *Client) Delete(ctx context.Context, p string) (*vaultapi.Secret, error) {
	return d.DeleteWithData(ctx, p, nil)
}

func (d *Client) DeleteWithData(ctx context.Context, p string, data map[string][]string) (*vaultapi.Secret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.address+"/v1/"+p, http.NoBody)
	if err != nil {
		return nil, err
	}

	var values url.Values
	for k, v := range data {
		if values == nil {
			values = make(url.Values)
		}
		for _, val := range v {
			values.Add(k, val)
		}
	}
	req.URL.RawQuery = values.Encode()

	resp, err := d.do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := vaultapi.ParseSecret(resp.Body)
		switch parseErr { //nolint:errorlint
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (d *Client) List(ctx context.Context, p string) (*vaultapi.Secret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.address+"/v1/"+p, http.NoBody)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("list", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := d.do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := vaultapi.ParseSecret(resp.Body)
		switch parseErr { //nolint:errorlint
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (d *Client) Raw(ctx context.Context, method string, path string, body any) (*vaultapi.Secret, error) {
	marshalled, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, d.address+"/v1/"+path, bytes.NewReader(marshalled))
	if err != nil {
		return nil, err
	}

	resp, err := d.do(req)
	if err != nil {
		return nil, err
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (d *Client) do(req *http.Request) (*http.Response, error) {
	d.modifyMutex.RLock()
	limiter := d.limiter
	token := d.token
	timeout := d.timeout
	d.modifyMutex.RUnlock()

	reqCtx := req.Context()
	if limiter != nil {
		limiterSpan, limiterCtx := tracer.StartSpanFromContext(reqCtx, "rate.Limiter")
		err := limiter.WaitNWithCallback(limiterCtx, 1, func(delay time.Duration) {
			escapedPath := req.URL.EscapedPath()
			metricTags := []metrics.Label{
				{Name: httpPath, Value: escapedPath},
				{Name: httpMethod, Value: req.Method},
			}
			if delay > 0 {
				d.log.Warn("Vault request delayed due to rate limiting",
					zap.Int64("delay_milliseconds", delay.Milliseconds()),
					zap.String(httpMethod, req.Method),
					zap.String(httpPath, escapedPath),
				)

				metricTags = append(metricTags, rateLimitDelayed)
			} else {
				metricTags = append(metricTags, rateLimitUntouched)
			}

			d.metricSink.IncrCounterWithLabels(statsdVaultRequest, 1.0, metricTags)
		})
		limiterSpan.Finish()
		if err != nil {
			return nil, err
		}
	}

	req.Header.Add(xVaultRequest, "true")
	req.Header.Add(xVaultToken, token)

	retryableReq, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, err
	}

	if timeout != 0 {
		// Note: we purposefully do not call cancel manually. The reason is
		// when canceled, the request.Body will EOF when reading due to the way
		// it streams data in. Cancel will still be run when the timeout is
		// hit, so this doesn't really harm anything.
		ctx, _ := context.WithTimeout(reqCtx, timeout) //nolint:govet
		_ = req.WithContext(ctx)
	}

	resp, err := d.retryableHTTPClient.Do(retryableReq)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func ObservedRetryPolicy(log *zap.Logger, metricSink metrics.MetricSink) func(ctx context.Context, resp *http.Response, err error) (bool, error) {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		retry, err := vaultapi.DefaultRetryPolicy(ctx, resp, err)
		if retry {
			logFields, metricLabels := make([]zap.Field, 0, 3), make([]metrics.Label, 0, 2)

			if resp != nil && resp.Request != nil {
				escapedPath := resp.Request.URL.EscapedPath()

				logFields = append(logFields,
					zap.String(httpMethod, resp.Request.Method),
					zap.String(httpPath, escapedPath),
					zap.Int(httpStatusCode, resp.StatusCode),
				)

				metricLabels = append(metricLabels,
					metrics.Label{Name: httpPath, Value: escapedPath},
					metrics.Label{Name: httpMethod, Value: resp.Request.Method},
				)
			}

			log.Warn("retrying Vault request due to failure", logFields...)

			metricSink.IncrCounterWithLabels(statsdVaultRequestHTTPRetry, 1.0, metricLabels)
		}

		return retry, err
	}
}
