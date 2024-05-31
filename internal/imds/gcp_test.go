package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/DataDog/attache/internal/cache"
	ddvault "github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

const (
	mountPath = "fake-vault-mount-path"
	iamRole   = "fake-iam-role"
)

var testProjects = map[string]string{}

func Test_gcpProvider_handleProjectId(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
	})
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	// Successful project-id lookup
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/project/project-id", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "project-id-test", string(body))

	// Failed to parse project-id
	_, err = v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": "foobar",
	})
	require.NoError(t, err)

	r, err = createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/project/project-id", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, "Internal Server Error\n", string(body))

	// Failed to lookup project-id
	_, err = v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": nil,
	})
	require.NoError(t, err)

	r, err = createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/project/project-id", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, "Internal Server Error\n", string(body))
}

func Test_gcpProvider_handleSlashRedir(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	require.NoError(t, err)

	paths := []string{
		"computeMetadata",
		"computeMetadata/v1",
		"computeMetadata/v1/instance/service-accounts",
		"computeMetadata/v1/instance/service-accounts/foobar",
		"computeMetadata/v1/project",
		"computeMetadata/v1/instance",
		"computeMetadata/v1/instance/attributes",
	}

	for _, p := range paths {
		// Successful redirect
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/"+p, nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusMovedPermanently, resp.Code, "invalid response code for %v", p)
		assert.Equal(t, "Google", resp.Header().Get("Metadata-Flavor"))
	}

	// Missing Metadata-Flavor header
	for _, p := range paths {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/"+p, nil)

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusForbidden, resp.Code, "invalid response code for %v", p)
		assert.Equal(t, "Google", resp.Header().Get("Metadata-Flavor"))
	}
}

func Test_gcpProvider_handlePing(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	paths := []string{
		"/",
		"/computeMetadata/",
		"/computeMetadata/v1/",
		"/computeMetadata/v1/instance/",
	}

	for _, p := range paths {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost"+p, nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.NotEmpty(t, resp.Body, "response body should not be nil or empty")
		assert.Equal(t, "Google", resp.Header().Get("Metadata-Flavor"))
	}
}

func Test_gcpProvider_handleEmail(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
	})
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/email", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "foobar@project-id-test.iam.gserviceaccount.com", string(body))

	// configured service account doesn't match
	r, err = createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/email", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, fmt.Sprintln(http.StatusText(http.StatusInternalServerError)), string(body))

	// default service account match
	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/default/email", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "foobar@project-id-test.iam.gserviceaccount.com", string(body))
}

func Test_gcpProvider_handleIdentity(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/identity", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.Equal(t, "OIDC tokens not supported\n", string(body))
}

func Test_gcpProvider_handleScopes(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/scopes", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform\nhttps://www.googleapis.com/auth/userinfo.email\n", string(body))
}

func Test_gcpProvider_handleNotImplemented(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	paths := []string{
		"computeMetadata/v1/instance/attributes/",
		"computeMetadata/v1/instance/attributes/foobar",
		"computeMetadata/v1/project/",
		"computeMetadata/v1/instance/id",
		"computeMetadata/v1/instance/zone",
		"computeMetadata/v1/instance/cpu-platform",
	}

	for _, p := range paths {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/"+p, nil)

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusNotImplemented, resp.Code)
		assert.Equal(t, "Not Implemented\n", string(body))
	}
}

func createGcpRouterWithVaultFetcher(t *testing.T, v *ddvault.Client) (*muxt.Router, error) {
	t.Helper()

	fetcher, err := NewGcpVaultTokenFetcher(v, iamRole, mountPath, testProjects, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	return createGcpRouter(t, fetcher, fetcher)
}

func createGcpRouter(t *testing.T, tokenGetter cache.Fetcher[*GcpCredentials], serviceAccountInfoGetter GcpServiceAccountInfoGetter) (*muxt.Router, error) {
	t.Helper()
	log := zaptest.NewLogger(t)
	p, err := Gcp(context.Background(), log, &metrics.BlackholeSink{}, tokenGetter, serviceAccountInfoGetter, cache.NewPercentageRemainingRefreshAt(1, 0))
	if err != nil {
		return nil, err
	}

	return createRouter(p, log)
}

func createRouter(provider *GcpProvider, log *zap.Logger) (*muxt.Router, error) {
	r := muxt.NewRouter()

	factory := NewHandlerFactory(&metrics.BlackholeSink{}, log)
	err := provider.RegisterHandlers(r, factory)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func Test_gcpProvider_handleServiceAccounts(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
	})
	require.NoError(t, err)

	r, err := createGcpRouterWithVaultFetcher(t, v)
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "default/\nfoobar@project-id-test.iam.gserviceaccount.com/\n", string(body))
}

func Test_gcpProvider_handleToken(t *testing.T) {
	t.Run("roleset", func(t *testing.T) {
		v := newVaultCluster(t)

		configureVaultCluster(t, v)
		_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
			"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
		})
		require.NoError(t, err)

		_, err = v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole, "token"), map[string]interface{}{
			"token":              "s.SuPeRsEcReTtOkEn",
			"expires_at_seconds": int(time.Now().Add(1 * time.Minute).Unix()),
			"token_ttl":          "1234",
		})
		require.NoError(t, err)

		r, err := createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.Code)

		var actual gcpCredentialsResponse
		err = json.Unmarshal(body, &actual)
		assert.NoError(t, err)
		assert.Equal(t, "s.SuPeRsEcReTtOkEn", actual.AccessToken)
		assert.Equal(t, "Bearer", actual.TokenType)
		assert.GreaterOrEqual(t, actual.ExpiresIn, 0)

		// configured service account doesn't match
		r, err = createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, resp.Code)
		assert.Equal(t, fmt.Sprintln(http.StatusText(http.StatusInternalServerError)), string(body))

		// canceled request
		canceledCtx, cancelCtxFn := context.WithCancel(context.Background())
		cancelCtxFn()

		req, _ = http.NewRequestWithContext(canceledCtx, "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, statusClientClosedRequest, resp.Code)
		assert.Contains(t, string(body), statusClientClosedRequestText)
	})

	t.Run("impersonated-account", func(t *testing.T) {
		v := newVaultCluster(t)

		configureVaultCluster(t, v)
		_, err := v.Write(context.Background(), path.Join(mountPath, "impersonated-account", iamRole), map[string]interface{}{
			"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
		})
		require.NoError(t, err)

		_, err = v.Write(context.Background(), path.Join(mountPath, "impersonated-account", iamRole, "token"), map[string]interface{}{
			"token":              "s.SuPeRsEcReTtOkEn",
			"expires_at_seconds": int(time.Now().Add(1 * time.Minute).Unix()),
			"token_ttl":          "1234",
		})
		require.NoError(t, err)

		r, err := createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.Code)

		var actual gcpCredentialsResponse
		err = json.Unmarshal(body, &actual)
		assert.NoError(t, err)
		assert.Equal(t, "s.SuPeRsEcReTtOkEn", actual.AccessToken)
		assert.Equal(t, "Bearer", actual.TokenType)
		assert.GreaterOrEqual(t, actual.ExpiresIn, 0)

		// configured service account doesn't match
		r, err = createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, resp.Code)
		assert.Equal(t, fmt.Sprintln(http.StatusText(http.StatusInternalServerError)), string(body))

		// canceled request
		canceledCtx, cancelCtxFn := context.WithCancel(context.Background())
		cancelCtxFn()

		req, _ = http.NewRequestWithContext(canceledCtx, "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/token", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, statusClientClosedRequest, resp.Code)
		assert.Contains(t, string(body), statusClientClosedRequestText)
	})
}

func Test_gcpProvider_handleServiceAccount(t *testing.T) {
	t.Run("roleset", func(t *testing.T) {
		v := newVaultCluster(t)

		configureVaultCluster(t, v)
		_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
			"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
		})
		require.NoError(t, err)

		r, err := createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "{\"aliases\":[\"default\"],\"email\":\"foobar@project-id-test.iam.gserviceaccount.com\",\"scopes\":[\"https://www.googleapis.com/auth/cloud-platform\"]}\n", string(body))

		// configured service account doesn't match
		r, err = createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, resp.Code)
		assert.Equal(t, fmt.Sprintln(http.StatusText(http.StatusInternalServerError)), string(body))
	})

	t.Run("impersonated-account", func(t *testing.T) {
		v := newVaultCluster(t)

		configureVaultCluster(t, v)
		_, err := v.Write(context.Background(), path.Join(mountPath, "impersonated-account", iamRole), map[string]interface{}{
			"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
		})
		require.NoError(t, err)

		r, err := createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar@project-id-test.iam.gserviceaccount.com/", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "{\"aliases\":[\"default\"],\"email\":\"foobar@project-id-test.iam.gserviceaccount.com\",\"scopes\":[\"https://www.googleapis.com/auth/cloud-platform\"]}\n", string(body))

		// configured service account doesn't match
		r, err = createGcpRouterWithVaultFetcher(t, v)
		assert.NoError(t, err)

		req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/instance/service-accounts/foobar/", nil)
		req.Header.Add("Metadata-Flavor", "Google")

		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, resp.Code)
		assert.Equal(t, fmt.Sprintln(http.StatusText(http.StatusInternalServerError)), string(body))
	})
}

func TestGcpProvider_handleNumericProjectID(t *testing.T) {
	tests := map[string]struct {
		mountPath      string
		expected       string
		expectedStatus int
	}{
		"valid mount path": {
			mountPath:      "cloud-iam/gcp/example",
			expected:       "1234567890",
			expectedStatus: http.StatusOK,
		},
		"invalid mount path": {
			mountPath:      "invalid",
			expected:       "Internal Server Error\n",
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for tn, tt := range tests {
		v, err := ddvault.NewClient(ddvault.DefaultConfig())
		require.NoError(t, err)

		projects := map[string]string{
			"cloud-iam/gcp/example": "1234567890",
		}
		fetcher, err := NewGcpVaultTokenFetcher(v, iamRole, tt.mountPath, projects, zap.L(), &metrics.BlackholeSink{})
		require.NoError(t, err)

		t.Run(tn, func(t *testing.T) {
			log := zaptest.NewLogger(t)
			p, err := Gcp(context.Background(), log, &metrics.BlackholeSink{}, fetcher, fetcher, cache.NewPercentageRemainingRefreshAt(1, 0))
			require.NoError(t, err)

			r, err := createRouter(p, log)
			require.NoError(t, err)

			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/computeMetadata/v1/project/numeric-project-id", nil)
			req.Header.Add("Metadata-Flavor", "Google")

			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, req)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.Code)
			assert.Equal(t, tt.expected, string(body))
		})
	}
}

func Test_gcpProvider_Name(t *testing.T) {
	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	fetcher, err := NewGcpVaultTokenFetcher(v, iamRole, mountPath, testProjects, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	p, err := Gcp(context.Background(), zaptest.NewLogger(t), &metrics.BlackholeSink{}, fetcher, fetcher, cache.NewPercentageRemainingRefreshAt(1, 0))
	assert.NoError(t, err)
	assert.Equal(t, "gcp", p.Name())
}

func TestGcp(t *testing.T) {
	log := zaptest.NewLogger(t)
	metricSink := &metrics.BlackholeSink{}

	f := cache.NewPercentageRemainingRefreshAt(1, 0)

	v, err := ddvault.NewClient(ddvault.DefaultConfig())
	require.NoError(t, err)

	// only used for parameter validation
	fetcher, err := NewGcpVaultTokenFetcher(v, iamRole, mountPath, testProjects, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	p, err := Gcp(context.Background(), log, metricSink, fetcher, fetcher, f)
	assert.NoError(t, err)
	assert.NotNil(t, p)

	p, err = Gcp(context.Background(), nil, metricSink, fetcher, fetcher, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Gcp(context.Background(), log, nil, fetcher, fetcher, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Gcp(context.Background(), log, metricSink, nil, fetcher, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Gcp(context.Background(), log, metricSink, fetcher, nil, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Gcp(context.Background(), log, metricSink, fetcher, fetcher, nil)
	assert.Error(t, err)
	assert.Nil(t, p)
}

// Test to make sure once a serviceaccount has been looked up, it is.
func Test_gcpProvider_lookupServiceAccount(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(context.Background(), path.Join(mountPath, "roleset", iamRole), map[string]interface{}{
		"service_account_email": "foobar@project-id-test.iam.gserviceaccount.com",
	})
	require.NoError(t, err)

	fetcher, err := NewGcpVaultTokenFetcher(v, "fake-iam-role", mountPath, testProjects, zap.L(), &metrics.BlackholeSink{})
	assert.NoError(t, err)
	assert.NotNil(t, fetcher)

	sa, err := fetcher.lookupServiceAccount(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "foobar@project-id-test.iam.gserviceaccount.com", sa)

	fetcher, err = NewGcpVaultTokenFetcher(v, "fake-iam-role", "/does/not/exist", testProjects, zap.L(), &metrics.BlackholeSink{})
	assert.NoError(t, err)
	assert.NotNil(t, fetcher)

	sa, err = fetcher.lookupServiceAccount(context.Background())
	assert.Error(t, err)
	assert.Equal(t, "role \"fake-iam-role\" does not exist: could not find impersonated account or rolepath, tried \"/does/not/exist/impersonated-account/fake-iam-role\" and \"/does/not/exist/roleset/fake-iam-role\"", err.Error())
	assert.Equal(t, "", sa)
}

func configureVaultCluster(t *testing.T, client *ddvault.Client) {
	t.Helper()

	data := &vaultapi.MountInput{Type: "kv"}
	_, err := client.Raw(context.Background(), http.MethodPost, path.Join("sys/mounts", mountPath), data)
	require.NoError(t, err)
}
