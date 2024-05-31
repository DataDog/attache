package imds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/retry"
	"github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	labelAzureProvider = metrics.Label{Name: "provider", Value: "azure"}
)

// AzureProvider implements identity portion of the Azure Instance Metadata service.
type AzureProvider struct {
	maintainers          map[string]*cache.Maintainer[*AzureCredentials]
	resourceTokenMutex   map[string]*sync.Mutex
	mutexMapMutex        sync.RWMutex
	retryOpts            []retry.Option
	refreshFunc          cache.RefreshAtFunc
	ctx                  context.Context
	tokenFetcherFactory  AzureTokenFetcherFactory
	subscriptionIDGetter AzureSubscriptionIDGetter

	log        *zap.Logger
	metricSink metrics.MetricSink
}

type AzureTokenFetcherFactory = func(resource string) (cache.Fetcher[*AzureCredentials], error)

// Azure returns a new AzureProvider.
func Azure(
	ctx context.Context,
	log *zap.Logger,
	metricSink metrics.MetricSink,
	refreshFunc cache.RefreshAtFunc,
	tokenFetcherFactory AzureTokenFetcherFactory,
	subscriptionIDGetter AzureSubscriptionIDGetter,
	retryOpts ...retry.Option,
) (*AzureProvider, error) {
	if ctx == nil {
		return nil, errors.New("ctx cannot be nil")
	}

	if log == nil {
		return nil, errors.New("log cannot be nil")
	}

	if metricSink == nil {
		return nil, errors.New("metricSink cannot be nil")
	}

	if refreshFunc == nil {
		return nil, errors.New("refresh func cannot be nil")
	}

	return &AzureProvider{
		log:        log,
		metricSink: metricSink,

		resourceTokenMutex:   map[string]*sync.Mutex{},
		maintainers:          map[string]*cache.Maintainer[*AzureCredentials]{},
		ctx:                  ctx,
		tokenFetcherFactory:  tokenFetcherFactory,
		subscriptionIDGetter: subscriptionIDGetter,

		refreshFunc: refreshFunc,
		retryOpts:   retryOpts,
	}, nil
}

// Name returns the provider's logical name.
func (p *AzureProvider) Name() string {
	return "azure"
}

// RegisterHandlers registers all HTTP handlers for the Azure provider.
func (p *AzureProvider) RegisterHandlers(router *muxt.Router, handlerFactory *HandlerFactory) error {
	router.Handle(
		"/metadata/identity/oauth2/token",
		metadataHeaderVerifier(azureResourceVerifier(azureAPIVersionVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleGetToken)))),
	)

	router.Handle(
		"/metadata/instance/compute/subscriptionId",
		metadataHeaderVerifier(azureAPIVersionVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleGetSubscriptionID))),
	)

	return nil
}

func (p *AzureProvider) handleGetSubscriptionID(logger *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	subscriptionID, err := p.subscriptionIDGetter.getSubscriptionID(r.Context())
	if err != nil {
		return fmt.Errorf("unable to get azure vault config: %w", err)
	}

	logger.Debug("fetched azure config")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if _, err := io.WriteString(w, subscriptionID); err != nil {
		return err
	}

	return nil
}

func (p *AzureProvider) handleGetToken(logger *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		resource = "https://management.azure.com/"
	}

	// Pass background context to ignore cancellation signal and cache
	// credentials in case of low timeout on imds client. Retried requests
	// by client should eventually succeed once cached credentials are
	// populated.
	//
	// The parent span is copied to include upstream calls in any trace.
	reqSpan, _ := tracer.SpanFromContext(r.Context())
	reqCtx := tracer.ContextWithSpan(context.Background(), reqSpan)

	token, err := p.getToken(reqCtx, logger, resource)
	if err != nil {
		return fmt.Errorf("unable to get azure access token: %w", err)
	}

	if r.Context().Err() != nil {
		return r.Context().Err()
	}

	logger.Debug("fetched azure access token")

	expiresOn, err := parseExpiresOn(token.ExpiresOn)
	if err != nil {
		return fmt.Errorf("unable to parse expires_on (%q): %w", token.ExpiresOn, err)
	}

	// recalculate expires_in since token is cached
	seconds := int(time.Until(*expiresOn).Seconds())
	token.ExpiresIn = strconv.Itoa(seconds)

	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(token)
}

func (p *AzureProvider) getMutexForResource(resource string) *sync.Mutex {
	p.mutexMapMutex.RLock()
	mutex, ok := p.resourceTokenMutex[resource]
	p.mutexMapMutex.RUnlock()
	if ok {
		return mutex
	}

	p.mutexMapMutex.Lock()
	defer p.mutexMapMutex.Unlock()

	mutex, ok = p.resourceTokenMutex[resource]
	if ok {
		return mutex
	}

	mutex = &sync.Mutex{}
	p.resourceTokenMutex[resource] = mutex

	return mutex
}

func (p *AzureProvider) getToken(ctx context.Context, log *zap.Logger, resource string) (*AzureCredentials, error) {
	mutex := p.getMutexForResource(resource)
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := p.maintainers[resource]; !ok {
		azureFetcher, err := p.tokenFetcherFactory(resource)
		if err != nil {
			return nil, fmt.Errorf("failed to create azure token fetcher for resource %s: %w", resource, err)
		}

		p.maintainers[resource] = cache.NewMaintainer[*AzureCredentials](
			azureFetcher,
			p.refreshFunc,
			cache.WithLogger(log.Named("token maintainer")),
			cache.WithMetricsSink(p.metricSink),
			cache.WithRetryOptions(p.retryOpts),
		)
	}

	result, err := p.maintainers[resource].Get(ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

const invalidRequest = "invalid_request"

type azureResponseError struct {
	error       string
	description string
}

func (e *azureResponseError) Error() string {
	return fmt.Sprintf("{\"error\":\"%v\",\"error_description\":\"%v\"}", e.error, e.description)
}

// metadataHeaderVerifier ensures that the HTTP request contains the "Metadata: true" header
// and ensures that the same header is set for responses.
func metadataHeaderVerifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata", "true")
		if r.Header.Get("Metadata") != "true" {
			e := &azureResponseError{error: invalidRequest, description: "Required metadata header not specified"}
			http.Error(w, e.Error(), http.StatusBadRequest)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func azureAPIVersionVerifier(next http.Handler) http.Handler {
	return azureQueryParamVerifier(next, "api-version")
}

func azureResourceVerifier(next http.Handler) http.Handler {
	return azureQueryParamVerifier(next, "resource")
}

func azureQueryParamVerifier(next http.Handler, paramName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiVersion := r.URL.Query().Get(paramName)
		if apiVersion == "" {
			e := &azureResponseError{
				error:       invalidRequest,
				description: fmt.Sprintf("Required query variable '%v' is missing", paramName),
			}

			http.Error(w, e.Error(), http.StatusBadRequest)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// AzureCredentials fields are documented here:
// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http
type AzureCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`

	ExpiresIn string `json:"expires_in"`
	ExpiresOn string `json:"expires_on"`
	NotBefore string `json:"not_before"`

	Resource string `json:"resource"`
	Type     string `json:"token_type"`
}

const (
	// For Azure expires_on formats see:
	// https://github.com/Azure/go-autorest/blob/10e0b31633f168ce1a329dcbdd0ab9842e533fb5/autorest/adal/token.go#L85-L89

	// the format for expires_on in UTC with AM/PM.
	expiresOnDateFormatPM = "1/2/2006 15:04:05 PM +00:00"

	// the format for expires_on in UTC without AM/PM.
	expiresOnDateFormat = "1/2/2006 15:04:05 +00:00"
)

// parseExpiresOn converts expires_on to time.Time.
func parseExpiresOn(s string) (*time.Time, error) {
	if seconds, err := strconv.ParseInt(s, 10, 64); err == nil {
		eo := time.Unix(seconds, 0)

		return &eo, nil
	} else if eo, err := time.Parse(expiresOnDateFormatPM, s); err == nil {
		t := eo.UTC()

		return &t, nil
	} else if eo, err := time.Parse(expiresOnDateFormat, s); err == nil {
		t := eo.UTC()

		return &t, nil
	} else {
		return nil, err
	}
}

type azureVaultTokenFetcher struct {
	vault              *vault.Client
	vaultTokenEndpoint string

	resource   string
	metricSink metrics.MetricSink
}

func NewAzureVaultTokenFetcher(
	vault *vault.Client,
	vaultMountPath, iamRole, resource string,
	metricSink metrics.MetricSink,
) (cache.Fetcher[*AzureCredentials], error) {
	if vault == nil {
		return nil, errors.New("vault client cannot be nil")
	}

	if vaultMountPath == "" {
		return nil, errors.New("vaultMountPath cannot be empty")
	}

	if iamRole == "" {
		return nil, errors.New("iamRole cannot be empty")
	}

	if resource == "" {
		return nil, errors.New("resource cannot be empty")
	}

	if metricSink == nil {
		return nil, errors.New("metric sink cannot be nil")
	}

	return &azureVaultTokenFetcher{
		vault:              vault,
		vaultTokenEndpoint: path.Join(vaultMountPath, "token", iamRole),
		resource:           resource,
		metricSink:         metricSink,
	}, nil
}

func (a *azureVaultTokenFetcher) String() string {
	return "azure-token-vault"
}

func (a *azureVaultTokenFetcher) Fetch(ctx context.Context) (creds *cache.ExpiringValue[*AzureCredentials], err error) {
	fetchSpan, ctx := tracer.StartSpanFromContext(ctx, "AzureVaultTokenFetcher.Fetch")
	defer func() {
		fetchSpan.Finish(tracer.WithError(err))

		statusLabel := labelSuccess
		if err != nil {
			statusLabel = labelFail
		}

		labels := []metrics.Label{labelAzureProvider, labelVaultMethod, statusLabel}
		a.metricSink.IncrCounterWithLabels(statsdCloudCredRequest, 1, labels)
	}()

	now := timeNow()
	secret, err := a.vault.ReadWithData(ctx, a.vaultTokenEndpoint, map[string][]string{"resource": {a.resource}})
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, newRoleDoesNotExistError(a.vaultTokenEndpoint)
	}

	result := &AzureCredentials{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   result,
		TagName:  "json",
	})
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(secret.Data)
	if err != nil {
		return nil, err
	}

	expiresIn, err := strconv.ParseInt(result.ExpiresIn, 10, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to convert expires_in (%q): %w", result.ExpiresIn, err)
	}
	expiresOn := now.Add(time.Duration(expiresIn) * time.Second)
	result.ExpiresOn = strconv.FormatInt(expiresOn.Unix(), 10)

	return &cache.ExpiringValue[*AzureCredentials]{
		Value:     result,
		ExpiresAt: expiresOn,
	}, nil
}
