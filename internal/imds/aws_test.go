package imds

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/vault"
	ec2imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

var awsTimeFormat = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

var nilIdentifier = &staticAwsIdentifier{}

func Test_awsProvider_lookupRole(t *testing.T) {
	v := newVaultCluster(t)

	configureVaultCluster(t, v)

	tests := map[string]struct {
		awsRoleArns   []string
		expectedRole  *role
		expectedError string
		mountPath     string
	}{
		"valid role configuration": {
			awsRoleArns: []string{"arn:aws:iam::123456789:role/super-duper-role"},
			expectedRole: &role{
				name: "super-duper-role",
				arn:  "arn:aws:iam::123456789:role/super-duper-role",
			},
			expectedError: "",
			mountPath:     mountPath,
		},
		"no arns configured": {
			awsRoleArns:   []string{},
			expectedRole:  nil,
			expectedError: "vault role must have at least one role_arn defined",
			mountPath:     mountPath,
		},
		"multiple role arns configured": {
			awsRoleArns:   []string{"arn:aws:iam::123456789:role/super-duper-role", "arn:aws:iam::123456789:role/super-duper-role2"},
			expectedRole:  nil,
			expectedError: "cannot have multiple role_arns defined for a Vault role",
			mountPath:     mountPath,
		},
		"invalid arn": {
			awsRoleArns:   []string{"arn:aws:iam::123456789:blah/super-duper-role"},
			expectedRole:  nil,
			expectedError: "unable to extract role from role ARN",
			mountPath:     mountPath,
		},
		"non-existent mount path": {
			awsRoleArns:   []string{"arn:aws:iam::123456789:blah/super-duper-role"},
			expectedRole:  nil,
			expectedError: `role "/does/not/exist/roles/fake-iam-role" does not exist`,
			mountPath:     "/does/not/exist",
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			_, err := v.Write(context.Background(), path.Join(mountPath, "roles", iamRole), map[string]interface{}{
				"role_arns": tt.awsRoleArns,
			})
			require.NoError(t, err)

			fetcher, err := NewVaultAwsStsTokenFetcher(v, iamRole, tt.mountPath, zap.L(), &metrics.BlackholeSink{})
			require.NoError(t, err)

			awsRole, err := fetcher.lookupRole(context.Background())
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedRole, awsRole)
		})
	}
}

func Test_awsProvider_Name(t *testing.T) {
	vaultdd, err := vault.NewClient(vault.DefaultConfig())
	require.NoError(t, err)

	fetcher, err := NewVaultAwsStsTokenFetcher(vaultdd, iamRole, mountPath, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	p, err := Aws(context.Background(), zaptest.NewLogger(t), false, &metrics.BlackholeSink{}, fetcher, fetcher, nilIdentifier, cache.NewPercentageRemainingRefreshAt(1, 0))
	assert.NoError(t, err)
	assert.Equal(t, "aws", p.Name())
}

func TestAws(t *testing.T) {
	log := zaptest.NewLogger(t)
	metricSink := &metrics.BlackholeSink{}
	vaultdd, err := vault.NewClient(vault.DefaultConfig())
	require.NoError(t, err)

	f := cache.NewPercentageRemainingRefreshAt(1, 0)

	fetcher, err := NewVaultAwsStsTokenFetcher(vaultdd, iamRole, mountPath, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	p, err := Aws(context.Background(), log, false, metricSink, fetcher, fetcher, nilIdentifier, f)
	assert.NoError(t, err)
	assert.NotNil(t, p)

	p, err = Aws(context.Background(), nil, false, metricSink, fetcher, fetcher, nilIdentifier, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Aws(context.Background(), log, false, nil, fetcher, fetcher, nilIdentifier, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Aws(context.Background(), log, false, metricSink, nil, fetcher, nilIdentifier, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Aws(context.Background(), log, false, metricSink, fetcher, nil, nilIdentifier, f)
	assert.Error(t, err)
	assert.Nil(t, p)

	p, err = Aws(context.Background(), log, false, metricSink, fetcher, fetcher, nilIdentifier, nil)
	assert.Error(t, err)
	assert.Nil(t, p)
}

func createAwsRouteWithVaultFetcher(t *testing.T, ctx context.Context, v *vault.Client, i InstanceIdentifier) (*muxt.Router, error) {
	t.Helper()

	fetcher, err := NewVaultAwsStsTokenFetcher(v, iamRole, mountPath, zap.L(), &metrics.BlackholeSink{})
	require.NoError(t, err)

	return createAwsRouter(t, ctx, i, fetcher, fetcher)
}

func createAwsRouter(t *testing.T, ctx context.Context, i InstanceIdentifier, fetcher cache.Fetcher[*AwsCredentials], roleGetter AwsRoleGetter) (*muxt.Router, error) {
	t.Helper()

	log := zaptest.NewLogger(t)

	if i == nil {
		i = &staticAwsIdentifier{}
	}

	p, err := Aws(ctx, log, true, &metrics.BlackholeSink{}, fetcher, roleGetter, i, cache.NewPercentageRemainingRefreshAt(1, 0))
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

func Test_awsProvider_handleSecurityCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
		"role_arns": []string{"arn:aws:iam::123456789:role/super-duper-role"},
	})
	require.NoError(t, err)

	r, err := createAwsRouteWithVaultFetcher(t, ctx, v, nil)
	assert.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/latest/meta-data/iam/security-credentials", nil)

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "super-duper-role", string(body))

	_, err = v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
		"role_arns": []string{"arn:aws:iam::123456789:blah/super-duper-role"},
	})
	require.NoError(t, err)

	r, err = createAwsRouteWithVaultFetcher(t, ctx, v, nil)
	assert.NoError(t, err)

	req, _ = http.NewRequestWithContext(context.TODO(), "GET", "http://localhost/latest/meta-data/iam/security-credentials", nil)

	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.Equal(t, "Internal Server Error\n", string(body))
}

func Test_awsProvider_handleSecurityCredentialsRole(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := newVaultCluster(t)

	configureVaultCluster(t, v)
	_, err := v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
		"role_arns": []string{"arn:aws:iam::123456789:role/super-duper-role"},
	})
	require.NoError(t, err)

	_, err = v.Write(ctx, path.Join(mountPath, "sts", iamRole), map[string]interface{}{
		"access_key":     "foo",
		"secret_key":     "bar",
		"security_token": "baz",
	})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, nil)
		require.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/latest/meta-data/iam/security-credentials/super-duper-role", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.Code)

		var actual AwsCredentials
		err = json.Unmarshal(body, &actual)
		assert.NoError(t, err)
		assert.Equal(t, "foo", actual.AccessKeyID)
		assert.Equal(t, "bar", actual.SecretAccessKey)
		assert.Equal(t, "baz", actual.Token)
		assert.Equal(t, 0, actual.Expiration.Nanosecond())
		assert.Equal(t, 0, actual.LastUpdated.Nanosecond())

		awsCredentialsRaw := struct {
			Expiration  string
			LastUpdated string
		}{}
		err = json.Unmarshal(body, &awsCredentialsRaw)
		assert.NoError(t, err)
		assert.True(t, awsTimeFormat.MatchString(awsCredentialsRaw.Expiration))
		assert.True(t, awsTimeFormat.MatchString(awsCredentialsRaw.LastUpdated))
	})

	t.Run("mismatch role error", func(t *testing.T) {
		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, nil)
		require.NoError(t, err)

		req, _ := http.NewRequestWithContext(context.TODO(), "GET", "http://localhost/latest/meta-data/iam/security-credentials/super-duper-role2", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.Code)
		assert.Equal(t, "Internal Server Error\n", string(body))
	})

	t.Run("context cancelled", func(t *testing.T) {
		_, err := v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
			"role_arns": []string{"arn:aws:iam::123456789:role/dd.fake_iamRole"},
		})
		require.NoError(t, err)

		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, nil)
		require.NoError(t, err)

		canceledCtx, cancelCtxFn := context.WithCancel(context.Background())
		cancelCtxFn()

		req, _ := http.NewRequestWithContext(canceledCtx, "GET", "http://localhost/latest/meta-data/iam/security-credentials/dd.fake_iamRole", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, statusClientClosedRequest, resp.Code)
		assert.Contains(t, string(body), statusClientClosedRequestText)
	})

}

func Test_imdsv2Verifier(t *testing.T) {
	noopHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	sessions := newIMDSSessionCache(ctx, &metrics.BlackholeSink{}, 100, time.Hour)
	valid, _, err := sessions.NewSession(time.Hour)
	assert.NoError(t, err)

	tests := map[string]struct {
		method  string
		headers map[string]string
		assert  func(t *testing.T, resp *http.Response)
	}{
		"no session token": {
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.Equal(t, resp.Header.Get("Server"), "EC2ws")
				assert.Empty(t, resp.Header.Get(awsEC2MetadataTokenTTLSeconds))
			},
		},
		"valid session token": {
			headers: map[string]string{awsEC2MetadataToken: valid.ID},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, resp.Header.Get("Server"), "EC2ws")
				ttl, err := strconv.Atoi(resp.Header.Get(awsEC2MetadataTokenTTLSeconds))
				assert.NoError(t, err)
				assert.Positive(t, ttl)
				assert.LessOrEqual(t, 1*time.Hour, time.Duration(ttl)*time.Second)
			},
		},
		"bad session token": {
			headers: map[string]string{awsEC2MetadataToken: "invalid-token"},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				assert.Equal(t, resp.Header.Get("Server"), "EC2ws")
			},
		},
		"bad http method": {
			method:  http.MethodPut,
			headers: map[string]string{awsEC2MetadataToken: valid.ID},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.Equal(t, resp.Header.Get("Server"), "EC2ws")
			},
		},
	}

	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			recorder := httptest.NewRecorder()

			imdsv2Verifier(false, sessions, noopHandler).ServeHTTP(recorder, req)

			resp := recorder.Result()
			tt.assert(t, resp)
			assert.NoError(t, resp.Body.Close())
		})
	}
}

func Test_awsProvider_handleIMDSV2Token(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := newVaultCluster(t)

	configureVaultCluster(t, v)

	_, err := v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
		"role_arns": []string{"arn:aws:iam::123456789:role/super-duper-role"},
	})
	require.NoError(t, err)

	r, err := createAwsRouteWithVaultFetcher(t, ctx, v, nil)
	assert.NoError(t, err)

	t.Run("generate expiring token", func(t *testing.T) {
		resp := testHandler(
			http.MethodPut, "/latest/api/token",
			map[string]string{awsEC2MetadataTokenTTLSeconds: "21600"},
			r,
		)
		token, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "21600", resp.Header.Get(awsEC2MetadataTokenTTLSeconds))
		assert.NotEmpty(t, token)

		resp = testHandler(
			http.MethodGet, "/latest/meta-data/iam/security-credentials",
			map[string]string{awsEC2MetadataToken: "invalid"},
			r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		resp = testHandler(
			http.MethodGet, "/latest/meta-data/iam/security-credentials",
			map[string]string{awsEC2MetadataToken: string(token)},
			r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, resp.Header.Get(awsEC2MetadataTokenTTLSeconds))

		// virtually advance time past ttl expiry
		timeNow = func() time.Time { return time.Now().Add(6 * time.Hour) }
		defer func() { timeNow = time.Now }()

		resp = testHandler(
			http.MethodGet, "/latest/meta-data/iam/security-credentials",
			map[string]string{awsEC2MetadataToken: string(token)},
			r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("reject x-forwarded-for", func(t *testing.T) {
		resp := testHandler(
			http.MethodPut, "/latest/api/token",
			map[string]string{
				"X-Forwarded-For":             "203.0.113.195",
				awsEC2MetadataTokenTTLSeconds: "21600",
			}, r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("reject > max ttl", func(t *testing.T) {
		resp := testHandler(
			http.MethodPut, "/latest/api/token",
			map[string]string{
				awsEC2MetadataTokenTTLSeconds: "21601",
			}, r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("require ttl value", func(t *testing.T) {
		resp := testHandler(
			http.MethodPut, "/latest/api/token",
			map[string]string{}, r,
		)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func Test_awsProvider_identityDocument(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := newVaultCluster(t)

	configureVaultCluster(t, v)

	_, err := v.Write(ctx, path.Join(mountPath, "roles", iamRole), map[string]interface{}{
		"role_arns": []string{"arn:aws:iam::123456789:role/super-duper-role"},
	})
	require.NoError(t, err)

	t.Run("region & zone on ec2 identity document on aws provider", func(t *testing.T) {
		i := NewAwsInstanceIdentifier("aws", "us-east-1", "us-east-1a")

		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, i)
		assert.NoError(t, err)

		resp := testHandler("GET", "/latest/dynamic/instance-identity/document", nil, r)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var have ec2imds.InstanceIdentityDocument
		assert.NoError(t, json.NewDecoder(resp.Body).Decode(&have))
		assert.NoError(t, resp.Body.Close())

		want := ec2imds.InstanceIdentityDocument{
			Region:           "us-east-1",
			AvailabilityZone: "us-east-1a",
		}
		assert.Equal(t, want, have)
	})

	t.Run("empty ec2 identity document on gcp provider", func(t *testing.T) {
		i := NewAwsInstanceIdentifier("gcp", "europe-west3", "europe-west3-a")

		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, i)
		assert.NoError(t, err)

		resp := testHandler("GET", "/latest/dynamic/instance-identity/document", nil, r)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var have ec2imds.InstanceIdentityDocument
		assert.NoError(t, json.NewDecoder(resp.Body).Decode(&have))
		assert.NoError(t, resp.Body.Close())

		want := ec2imds.InstanceIdentityDocument{}
		assert.Equal(t, want, have)
	})

	t.Run("empty ec2 identity document on azure provider", func(t *testing.T) {
		i := NewAwsInstanceIdentifier("azure", "westus2", "westus2-1")

		r, err := createAwsRouteWithVaultFetcher(t, ctx, v, i)
		assert.NoError(t, err)

		resp := testHandler("GET", "/latest/dynamic/instance-identity/document", nil, r)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var have ec2imds.InstanceIdentityDocument
		assert.NoError(t, json.NewDecoder(resp.Body).Decode(&have))
		assert.NoError(t, resp.Body.Close())

		want := ec2imds.InstanceIdentityDocument{}
		assert.Equal(t, want, have)
	})
}

func testHandler(
	method, path string,
	headers map[string]string,
	h http.Handler,
) *http.Response {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}

	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	return w.Result()
}
