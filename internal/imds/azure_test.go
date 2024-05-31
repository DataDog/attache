package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/vault"
	"github.com/fatih/structs"
	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

func structsMap(s interface{}) map[string]interface{} {
	t := structs.New(s)
	t.TagName = "json"

	return t.Map()
}

type providerParams struct {
	fetcherFactory       func(resource string) (cache.Fetcher[*AzureCredentials], error)
	subscriptionIDGetter AzureSubscriptionIDGetter
}

func createAzureRouter(t *testing.T, params *providerParams) (*muxt.Router, error) {
	t.Helper()

	log := zaptest.NewLogger(t)
	refreshFunc := cache.NewPercentageRemainingRefreshAt(1, 0)

	p, err := Azure(context.Background(), log, &metrics.BlackholeSink{}, refreshFunc, params.fetcherFactory, params.subscriptionIDGetter)
	if err != nil {
		return nil, err
	}

	r := muxt.NewRouter()

	factory := NewHandlerFactory(&metrics.BlackholeSink{}, log)
	err = p.RegisterHandlers(r, factory)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func createAzureProviderVaultParams(v *vault.Client) *providerParams {
	return &providerParams{
		fetcherFactory: func(resource string) (cache.Fetcher[*AzureCredentials], error) {
			return NewAzureVaultTokenFetcher(v, mountPath, "fake-iam-role", resource, &metrics.BlackholeSink{})
		},
		subscriptionIDGetter: NewAzureVaultSubscriptionIDGetter(v, mountPath),
	}
}

func Test_azureProvider_handleGetTokenVault(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)

	tenant, resource := "test-tenant", "https://resource.endpoint/"
	_, err := v.Write(context.Background(), path.Join(mountPath, "config"), map[string]interface{}{
		"environment":     "AzurePublicCloud",
		"tenant_id":       tenant,
		"subscription_id": "test-subscription",
		"client_id":       "test-vault-backend-client-id",
	})
	require.NoError(t, err)

	expiresOn := time.Now().UTC().Add(1 * time.Hour)
	expiresOnStr := strconv.FormatInt(expiresOn.Unix(), 10)
	_, err = v.Write(context.Background(), path.Join(mountPath, "token", iamRole), structsMap(AzureCredentials{
		AccessToken: "test-access-token",
		ExpiresOn:   expiresOnStr,
		ExpiresIn:   "3600",
		NotBefore:   expiresOnStr,
		Resource:    resource,
		Type:        "Bearer",
	}))
	require.NoError(t, err)

	r, err := createAzureRouter(t, createAzureProviderVaultParams(v))
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/metadata/identity/oauth2/token?resource=https%3A%2F%2Fresource.endpoint%2F&api-version=2020-02-02", nil)
	req.Header.Add("Metadata", "true")
	recorder := httptest.NewRecorder()

	r.ServeHTTP(recorder, req)
	resp := recorder.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	var received AzureCredentials
	err = json.Unmarshal(body, &received)
	require.NoError(t, err)

	receivedExpiresIn, err := strconv.ParseInt(received.ExpiresIn, 10, 0)
	require.NoError(t, err)

	assert.Equal(t, "test-access-token", received.AccessToken)
	assert.Equal(t, expiresOnStr, received.ExpiresOn)
	assert.Less(t, receivedExpiresIn, int64(3600))
	assert.Equal(t, "https://resource.endpoint/", received.Resource)
	assert.Equal(t, "Bearer", received.Type)
	assert.NotEmpty(t, received.ExpiresIn)

	// canceled request
	canceledCtx, cancelCtxFn := context.WithCancel(context.Background())
	cancelCtxFn()

	req, _ = http.NewRequestWithContext(canceledCtx, "GET", "http://localhost/metadata/identity/oauth2/token?resource=https%3A%2F%2Fresource.endpoint%2F&api-version=2020-02-02", nil)
	req.Header.Add("Metadata", "true")
	recorder = httptest.NewRecorder()

	r.ServeHTTP(recorder, req)
	resp = recorder.Result()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, statusClientClosedRequest, resp.StatusCode)
	assert.Contains(t, string(body), statusClientClosedRequestText)
}

func Test_azureProvider_handleGetVaultSubscriptionID(t *testing.T) {
	v := newVaultCluster(t)
	configureVaultCluster(t, v)

	_, err := v.Write(context.Background(), path.Join(mountPath, "config"), map[string]interface{}{
		"environment":     "AzurePublicCloud",
		"tenant_id":       "test-tenant",
		"subscription_id": "test-subscription",
		"client_id":       "test-vault-backend-client-id",
	})
	require.NoError(t, err)

	r, err := createAzureRouter(t, createAzureProviderVaultParams(v))
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.TODO(), "GET", "http://localhost/metadata/instance/compute/subscriptionId?api-version=2017-08-01", nil)
	req.Header.Add("Metadata", "true")
	recorder := httptest.NewRecorder()

	r.ServeHTTP(recorder, req)
	resp := recorder.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "test-subscription", string(body))
}

func Test_verifyMetadataHeader(t *testing.T) {
	v := newVaultCluster(t)
	r, err := createAzureRouter(t, createAzureProviderVaultParams(v))
	assert.NoError(t, err)

	tests := map[string]struct {
		path string
	}{
		"handleSubscriptionID": {
			path: "/metadata/instance/compute/subscriptionId",
		},
		"handleToken": {
			path: "/metadata/identity/oauth2/token",
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost"+tt.path, nil)
			recorder := httptest.NewRecorder()

			r.ServeHTTP(recorder, req)
			resp := recorder.Result()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, "{\"error\":\"invalid_request\",\"error_description\":\"Required metadata header not specified\"}\n", string(body))
		})
	}
}

func Test_verifyQueryParameterExists(t *testing.T) {
	v := newVaultCluster(t)

	r, err := createAzureRouter(t, createAzureProviderVaultParams(v))
	assert.NoError(t, err)

	configureVaultCluster(t, v)

	tenant, resource := "test-tenant", "https://resource.endpoint/"
	_, err = v.Write(context.Background(), path.Join(mountPath, "config"), map[string]interface{}{
		"environment":     "AzurePublicCloud",
		"tenant_id":       tenant,
		"subscription_id": "test-subscription",
		"client_id":       "test-vault-backend-client-id",
	})
	require.NoError(t, err)

	nowTime := time.Now()
	_, err = v.Write(context.Background(), path.Join(mountPath, "token", iamRole), structsMap(AzureCredentials{
		AccessToken: "test-access-token",
		ExpiresIn:   "3600",
		ExpiresOn:   strconv.FormatInt(nowTime.Add(1*time.Hour).Unix(), 10),
		NotBefore:   strconv.FormatInt(nowTime.Unix(), 10),
		Resource:    resource,
		Type:        "Bearer",
	}))
	require.NoError(t, err)

	tests := map[string]struct {
		path       string
		missing    string
		httpStatus int
	}{
		"handleSubscriptionID missing api-version": {
			path:       "/metadata/instance/compute/subscriptionId?resource=blah",
			missing:    "api-version",
			httpStatus: http.StatusBadRequest,
		},
		"handleSubscriptionID valid request": {
			path:       "/metadata/instance/compute/subscriptionId?api-version=blah",
			missing:    "",
			httpStatus: http.StatusOK,
		},
		"handleToken missing resource": {
			path:       "/metadata/identity/oauth2/token?api-version=blah",
			missing:    "resource",
			httpStatus: http.StatusBadRequest,
		},
		"handleToken missing api-version": {
			path:       "/metadata/identity/oauth2/token?resource=blah",
			missing:    "api-version",
			httpStatus: http.StatusBadRequest,
		},
		"handleToken valid request": {
			path:       "/metadata/identity/oauth2/token?resource=blah&api-version=blah",
			missing:    "",
			httpStatus: http.StatusOK,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost"+tt.path, nil)
			req.Header.Add("Metadata", "true")
			recorder := httptest.NewRecorder()

			r.ServeHTTP(recorder, req)
			resp := recorder.Result()

			assert.Equal(t, tt.httpStatus, resp.StatusCode)

			if tt.httpStatus == http.StatusBadRequest {
				body, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				assert.Equal(t, fmt.Sprintf("{\"error\":\"invalid_request\",\"error_description\":\"Required query variable '%v' is missing\"}\n", tt.missing), string(body))
			}
		})
	}
}

func Test_parseExpiresOn(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)

	tests := map[string]struct {
		input   string
		want    *time.Time
		delta   time.Duration
		wantErr bool
	}{
		"successful integer parse": {
			input: strconv.FormatInt(now.Unix(), 10),
			want:  timePtr(t, now),
		},
		"successful datetime format parse": {
			input: now.Format(expiresOnDateFormat),
			want:  timePtr(t, now),
		},
		"successful datetime PM format parse": {
			input: now.Format(expiresOnDateFormatPM),
			want:  timePtr(t, now),
		},
		"invalid number": {
			input:   "123.123.123",
			wantErr: true,
		},
		"invalid datetime format": {
			input:   now.Format(time.RFC1123Z),
			wantErr: true,
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			got, err := parseExpiresOn(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExpiresOn() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if tt.want == nil {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				require.WithinDuration(t, *tt.want, *got, tt.delta)
			}
		})
	}
}

func timePtr(t *testing.T, b time.Time) *time.Time {
	t.Helper()

	return &b
}
