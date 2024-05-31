package imds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/rate"
	"github.com/DataDog/attache/internal/retry"
	"github.com/DataDog/attache/internal/server"
	"github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
)

// Config for metadata server.
type Config struct {
	// the cloud provider IAM role (e.g. for GCP, the service account)
	IamRole string `yaml:"iam_role"`

	// By default AWS IMDSv1 is disabled
	IMDSv1Allowed bool `yaml:"imds_v1_allowed"`

	// the Vault mount path for GCP
	GcpVaultMountPath string `yaml:"gcp_vault_mount_path"`

	// mapping from gcp project name to the gcp project id
	GcpProjectIds map[string]string `yaml:"gcp_project_ids"`

	// the Vault mount path for AWS
	AwsVaultMountPath string `yaml:"aws_vault_mount_path"`

	// the Vault mount path for Azure
	AzureVaultMountPath string `yaml:"azure_vault_mount_path"`

	// Server configuration
	ServerConfig server.Config `yaml:"server"`

	// the cloud provider (e.g., "aws")
	Provider string `yaml:"provider"`

	// the cloud provider region (e.g., "us-east-1")
	Region string `yaml:"region"`

	// the cloud provider zone (e.g., "us-east-1a")
	Zone string `yaml:"zone"`
}

// Validate a config.
func (c *Config) Validate() error {
	var result error

	if strings.TrimSpace(c.IamRole) == "" {
		result = multierror.Append(result, errors.New("IAM role cannot be empty"))
	}

	if err := c.ServerConfig.Validate(); err != nil {
		result = multierror.Append(result, fmt.Errorf("server configuration not valid: %w", err))
	}

	return result
}

type MetadataServerConfig struct {
	CloudiamConf  Config
	DDVaultClient *vault.Client

	MetricSink metrics.MetricSink
	Log        *zap.Logger
}

// NewServer creates a new metadata server.
func NewServer(ctx context.Context, conf *MetadataServerConfig) (*server.Server, func(), error) {
	log := decorateLog(conf.Log)
	router, closeFunc, err := newRouter(ctx, conf)
	if err != nil {
		return nil, func() {}, err
	}

	return server.NewServer(log, conf.CloudiamConf.ServerConfig, router, server.WithMetricSink(conf.MetricSink)), closeFunc, nil
}

func newRouter(ctx context.Context, conf *MetadataServerConfig) (*muxt.Router, func(), error) {
	// closeFunc is returned to the caller and handled cleaningup
	// any resources created in this method. (ex. cloudiam client managers)
	var cleanupFuncs []func()
	closeFunc := func() {
		for _, f := range cleanupFuncs {
			f()
		}
	}

	router := muxt.NewRouter(muxt.WithServiceName("attache.imds"), muxt.WithIgnoreRequest(func(req *http.Request) bool {
		// Skip tracing AWS API token requests because they are very frequent
		// and make no remote calls internally so aren't very interesting.
		// This saves on memory allocations.
		if req.RequestURI == "/latest/api/token" {
			return true
		}
		return false
	}))

	// NOTE: it would be better if the provider wasn't responsible for registering.
	// Then we could sanity check what was being registered to ensure that there were
	// no duplicates. However, that is not trivial because a handler can be registered
	// not only to a path but to a host, method, header, etc... therefore it is
	// imperative to have sufficient testing to ensure that routes are not being subsumed.
	factory := NewHandlerFactory(conf.MetricSink, conf.Log)
	p := []Provider{}

	// Refresh after 20m + jitter of [0,24s]
	//
	// The AWS SDKs for Go, Java, and Python have a common denominator of a
	// renewal window starting when there is 15min TTL remaining on the token.
	//
	// - aws-sdk-go 5m - https://github.com/aws/aws-sdk-go/blob/main/aws/defaults/defaults.go#L205
	// - botocore 15m - https://github.com/boto/botocore/blob/master/botocore/credentials.py#L377-L382
	// - aws-sdk-java 15m - https://github.com/aws/aws-sdk-java/blob/master/aws-java-sdk-core/src/main/java/com/amazonaws/auth/BaseCredentialsFetcher.java#L42-L46
	//
	// We do not want to increase this too close to the actual expiration of the
	// tokens (for all cloud providers this is currently 1hr) for the following
	// reasons:
	//
	// 1. If Attaché IMDS returns a token too near the expiration and a client
	//    uses it once expired without realizing that the client will receive
	//    an error due to the expired token.
	// 2. Cloud provider SDKs commonly try to retrieve a new token prior to the
	//    current active one expiring at a specific renew threshold. For AWS
	//    this is >10min before the current token expires. This means a call to
	//    AWS ends up first trying to retrieve a new token from Attaché. So
	//    for every request a client makes to the cloud provider between the
	//    renewal threshold and the token expiration, the client will try to call
	//    Attaché IMDS for a new token. This can result in performance issues
	//    in the application because of the extra call to linklocal Attaché
	//    IMDS and can also potentially cause Attaché to block if its request
	//    queue is backed up or even OOM.
	//
	// With a token refresh of 20m + jitter our Mean Time To Failure (MTTF) will
	// be 20m and a Least Time To Failure (LTTF) of 10m.
	refreshFunc := cache.NewPercentageRemainingRefreshAt(0.33333333, 0.10)
	retryOpts := []retry.Option{
		retry.MaxAttempts(4),
		retry.MaxJitter(2 * time.Minute),
		retry.InitialDelay(10 * time.Second),
	}

	cloudiamConf := conf.CloudiamConf

	if strings.TrimSpace(cloudiamConf.GcpVaultMountPath) != "" {
		var gcpServiceAccountInfoGetter GcpServiceAccountInfoGetter
		var gcpTokenGetter cache.Fetcher[*GcpCredentials]

		vaultFetcher, err := NewGcpVaultTokenFetcher(conf.DDVaultClient, cloudiamConf.IamRole, cloudiamConf.GcpVaultMountPath, cloudiamConf.GcpProjectIds, conf.Log, conf.MetricSink)
		if err != nil {
			return nil, closeFunc, fmt.Errorf("failed to create vault GCP token fetcher: %w", err)
		}

		gcpServiceAccountInfoGetter = vaultFetcher
		gcpTokenGetter = vaultFetcher

		gcpProvider, err := Gcp(ctx, conf.Log, conf.MetricSink, gcpTokenGetter, gcpServiceAccountInfoGetter, refreshFunc, retryOpts...)
		if err != nil {
			return nil, closeFunc, fmt.Errorf("unable to create GCP provider: %w", err)
		}
		p = append(p, gcpProvider)
	}

	if strings.TrimSpace(cloudiamConf.AwsVaultMountPath) != "" {
		identifier := NewAwsInstanceIdentifier(cloudiamConf.Provider, cloudiamConf.Region, cloudiamConf.Zone)

		var awsRoleGetter AwsRoleGetter
		var awsTokenFetcher cache.Fetcher[*AwsCredentials]

		vaultFetcher, err := NewVaultAwsStsTokenFetcher(conf.DDVaultClient, cloudiamConf.IamRole, cloudiamConf.AwsVaultMountPath, conf.Log, conf.MetricSink)
		if err != nil {
			return nil, closeFunc, fmt.Errorf("failed to create vault AWS token fetcher: %w", err)
		}

		awsRoleGetter = vaultFetcher
		awsTokenFetcher = vaultFetcher

		awsProvider, err := Aws(ctx, conf.Log, conf.CloudiamConf.IMDSv1Allowed, conf.MetricSink, awsTokenFetcher, awsRoleGetter, identifier, refreshFunc, retryOpts...)
		if err != nil {
			return nil, closeFunc, fmt.Errorf("unable to create AWS provider: %w", err)
		}
		p = append(p, awsProvider)
	}

	if strings.TrimSpace(cloudiamConf.AzureVaultMountPath) != "" {
		azureSubscriptionIDGetter := NewAzureVaultSubscriptionIDGetter(conf.DDVaultClient, cloudiamConf.AzureVaultMountPath)

		tokenFetcherFactory := func(resource string) (cache.Fetcher[*AzureCredentials], error) {
			vaultFetcher, err := NewAzureVaultTokenFetcher(conf.DDVaultClient, cloudiamConf.AzureVaultMountPath, cloudiamConf.IamRole, resource, conf.MetricSink)
			if err != nil {
				return nil, err
			}
			return vaultFetcher, nil
		}

		azureProvider, err := Azure(ctx, conf.Log, conf.MetricSink, refreshFunc, tokenFetcherFactory, azureSubscriptionIDGetter, retryOpts...)
		if err != nil {
			return nil, closeFunc, fmt.Errorf("unable to create Azure provider: %w", err)
		}
		p = append(p, azureProvider)
	}

	if len(p) == 0 {
		return nil, closeFunc, errors.New("no metadataserver providers registered")
	}

	for _, provider := range p {
		if err := provider.RegisterHandlers(router, factory); err != nil {
			return nil, closeFunc, fmt.Errorf("unable to register provider %v: %w", provider.Name(), err)
		}
	}

	// Limiter rate equal to len(p) for the steady state credential fetch from Vault,
	// effectively 1 request/s per cloud provider. Burst/bucket capacity of
	// (2 x len(p) + overhead) allowing for the initial credentials fetch which
	// requires an additional request for metadata plus a little overhead.
	totalProviders := len(p)
	conf.DDVaultClient.SetLimiter(rate.NewLimiter(rate.Limit(totalProviders), (2*totalProviders)+4))

	return router, closeFunc, nil
}

func decorateLog(log *zap.Logger) *zap.Logger {
	return log.Named("cloud-iam-server")
}
