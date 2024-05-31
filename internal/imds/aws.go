package imds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/retry"
	vaultclient "github.com/DataDog/attache/internal/vault"
	ec2imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-metrics"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// AwsRoleGetter returns the configured AWS IMDS role.
// This meant to be temporary and will be replaced once the AWS role name generated from
// the pod namespace and service account is passed directly to the AwsProvider.
type AwsRoleGetter interface {
	lookupRole(ctx context.Context) (*role, error)
}

// AwsProvider implements the AWS Metadata Service backed by Vault.
type AwsProvider struct {
	maintainer *cache.Maintainer[*AwsCredentials]
	roleGetter AwsRoleGetter
	sessions   *imdsSessionCache
	metricSink metrics.MetricSink
	identifier InstanceIdentifier
	v1Allowed  bool
}

const (
	defaultAwsCredTTL = time.Hour
)

var (
	awsRoleRegex = regexp.MustCompile(`.+:role\/(.+)$`)

	labelAwsProvider = metrics.Label{Name: "provider", Value: "aws"}
)

// timeNow is used for testing.
var timeNow = time.Now

// Aws returns a new AwsProvider.
func Aws(
	ctx context.Context,
	log *zap.Logger,
	v1Allowed bool,
	metricSink metrics.MetricSink,
	tokenFetcher cache.Fetcher[*AwsCredentials],
	roleGetter AwsRoleGetter,
	identifier InstanceIdentifier,
	refreshFunc cache.RefreshAtFunc, retryOpts ...retry.Option,
) (*AwsProvider, error) {
	if ctx == nil {
		return nil, errors.New("context cannote be nil")
	}

	if log == nil {
		return nil, errors.New("log cannot be nil")
	}

	if metricSink == nil {
		return nil, errors.New("metricSink cannot be nil")
	}

	if tokenFetcher == nil {
		return nil, errors.New("tokenFetcher cannot be nil")
	}

	if roleGetter == nil {
		return nil, errors.New("roleGetter cannot be nil")
	}

	if identifier == nil {
		return nil, errors.New("instance identity provider cannot be nil")
	}

	if refreshFunc == nil {
		return nil, errors.New("refresh func cannot be nil")
	}

	maintainer := cache.NewMaintainer[*AwsCredentials](
		tokenFetcher,
		refreshFunc,
		cache.WithLogger(log.Named("token maintainer")),
		cache.WithMetricsSink(metricSink),
		cache.WithRetryOptions(retryOpts),
	)

	p := &AwsProvider{
		maintainer: maintainer,
		roleGetter: roleGetter,
		sessions:   newIMDSSessionCache(ctx, metricSink, maxAwsEC2MetadataTokens, time.Minute),
		metricSink: metricSink,
		identifier: identifier,
		v1Allowed:  v1Allowed,
	}

	return p, nil
}

// Name returns the provider's logical name.
func (p *AwsProvider) Name() string {
	return "aws"
}

// RegisterHandlers registers all HTTP handlers for the AWS provider.
func (p *AwsProvider) RegisterHandlers(router *muxt.Router, handlerFactory *HandlerFactory) error {
	router.Handle(
		"/{version}/meta-data/iam/security-credentials",
		imdsv2Verifier(p.v1Allowed, p.sessions, handlerFactory.CreateHTTPHandler(p.Name(), p.handleSecurityCredentials)),
	)

	router.Handle(
		"/{version}/meta-data/iam/security-credentials/",
		imdsv2Verifier(p.v1Allowed, p.sessions, handlerFactory.CreateHTTPHandler(p.Name(), p.handleSecurityCredentials)),
	)

	router.Handle(
		"/{version}/meta-data/iam/security-credentials/{role:.+}",
		imdsv2Verifier(p.v1Allowed, p.sessions, handlerFactory.CreateHTTPHandler(p.Name(), p.handleSecurityCredentialsRole)),
	)

	router.Handle(
		"/{version}/api/token",
		imdsVersionTag(handlerFactory.CreateHTTPHandler(p.Name(), p.handleIMDSV2Token)),
	).Methods(http.MethodPut)

	router.Handle(
		"/{version}/dynamic/instance-identity/document",
		imdsVersionTag(handlerFactory.CreateHTTPHandler(p.Name(), p.handleIdentityDocument)),
	)

	return nil
}

func (p *AwsProvider) handleSecurityCredentialsRole(_ *zap.Logger, writer http.ResponseWriter, request *http.Request) error {
	awsRole, err := p.roleGetter.lookupRole(request.Context())
	if err != nil {
		return fmt.Errorf("error looking up IAM role arns: %w", err)
	}

	params := mux.Vars(request)
	requestedRole := params["role"]
	if awsRole.name != requestedRole {
		return errors.New("requested role not allowed")
	}

	// Pass background context to ignore cancellation signal and cache
	// credentials in case of low timeout on imds client. Retried requests
	// by client should eventually succeed once cached credentials are
	// populated.
	//
	// The parent span is copied to include upstream calls in any trace.
	reqSpan, _ := tracer.SpanFromContext(request.Context())
	reqCtx := tracer.ContextWithSpan(context.Background(), reqSpan)

	creds, err := p.maintainer.Get(reqCtx)
	if err != nil {
		return err
	}

	if request.Context().Err() != nil {
		return request.Context().Err()
	}

	return json.NewEncoder(writer).Encode(creds)
}

func (p *AwsProvider) handleSecurityCredentials(_ *zap.Logger, writer http.ResponseWriter, request *http.Request) error {
	role, err := p.roleGetter.lookupRole(request.Context())
	if err != nil {
		return fmt.Errorf("error looking up IAM role: %w", err)
	}

	_, err = writer.Write([]byte(role.name))

	return err
}

func (p *AwsProvider) handleIdentityDocument(_ *zap.Logger, writer http.ResponseWriter, request *http.Request) error {
	doc, err := p.identifier.GetInstanceIdentity(request.Context())
	if err != nil {
		return fmt.Errorf("getting instance identity document: %w", err)
	}

	return json.NewEncoder(writer).Encode(doc)
}

const (
	awsEC2MetadataTokenTTLSeconds = "X-aws-ec2-metadata-token-ttl-seconds"
	awsEC2MetadataToken           = "X-aws-ec2-metadata-token"
)

// handleIMDSV2Token generates session tokens for IMDSv2 http clients.
func (p *AwsProvider) handleIMDSV2Token(_ *zap.Logger, writer http.ResponseWriter, request *http.Request) error {
	writer.Header().Set("Server", "EC2ws")

	hdr := request.Header.Get(awsEC2MetadataTokenTTLSeconds)
	ttl, err := strconv.Atoi(hdr)

	switch {
	case err != nil || ttl < 0 || ttl > 21600:
		return HTTPError{
			code:  http.StatusBadRequest,
			error: errors.New("x-aws-ec2-metadata-token-ttl-seconds must be an integer between (0, 21600)"),
		}
	case request.Header.Get("X-Forwarded-For") != "":
		return HTTPError{
			code:  http.StatusForbidden,
			error: errors.New("X-Forwarded-For cannot be used with EC2 IMDS GetToken"),
		}
	}

	session, _, err := p.sessions.NewSession(time.Duration(ttl) * time.Second)
	if err != nil {
		return err
	}

	writer.Header().Set(awsEC2MetadataTokenTTLSeconds, strconv.Itoa(ttl))
	writer.Header().Set("Content-Type", "text/plain")

	if _, err := writer.Write([]byte(session.ID)); err != nil {
		return fmt.Errorf("writing token response: %w", err)
	}

	return nil
}

// imdsv2Verifier enforces validity of EC2 IMDSv2 session tokens provided via
// the X-aws-ec2-metadata-token header. If the header is not present, the
// request is as IMDSv1 format and allowed.
//
// For more details on EC2 IMDSv2, see the following documentation:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-v2-how-it-works
func imdsv2Verifier(v1Allowed bool, sessions *imdsSessionCache, next http.Handler) http.Handler {
	return imdsVersionTag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := timeNow()

		w.Header().Set("Server", "EC2ws")

		token := r.Header.Get(awsEC2MetadataToken)

		session, found := sessions.GetSession(token)

		switch {
		case token == "":
			// IMDSv1:
			if !v1Allowed {
				//IMDSv1 is disabled
				w.WriteHeader(http.StatusForbidden)
				return
			}
		case !found:
			// invalid or expired session token
			w.WriteHeader(http.StatusUnauthorized)
			return
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			// only Get & HEAD methods are allowed
			w.WriteHeader(http.StatusForbidden)
			return
		default:
			// annotate remaining token TTL in response
			ttl := fmt.Sprintf("%.0f", session.Expiry.Sub(now).Seconds())
			w.Header().Set(awsEC2MetadataTokenTTLSeconds, ttl)
		}

		next.ServeHTTP(w, r)
	}))
}

// imdsVersionTag annotates requests with the IMDS api version for telemetry.
func imdsVersionTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imds := "IMDSv1"

		if r.Header.Get(awsEC2MetadataToken) != "" ||
			r.Header.Get(awsEC2MetadataTokenTTLSeconds) != "" {
			imds = "IMDSv2"
		}

		// include imds version for instrumentation
		next.ServeHTTP(w, wrapRequestTag(r, "imds-version", imds))
	})
}

type role struct {
	name string
	arn  string
}

type AwsCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	Code            string
	Expiration      time.Time
	LastUpdated     time.Time
	SecretAccessKey string
	Token           string
	Type            string
}

type AwsVaultStsTokenFetcher struct {
	vault             *vaultclient.Client
	vaultStsEndpoint  string
	vaultRoleEndpoint string

	awsRole         *role
	lookupRoleMutex sync.Mutex

	log        *zap.Logger
	metricSink metrics.MetricSink
}

func NewVaultAwsStsTokenFetcher(vault *vaultclient.Client,
	iamRole, vaultMountPath string,
	log *zap.Logger,
	metricSink metrics.MetricSink,
) (*AwsVaultStsTokenFetcher, error) {
	if vault == nil {
		return nil, errors.New("vault client cannot be nil")
	}

	if iamRole == "" {
		return nil, errors.New("iam role cannot be empty")
	}

	if vaultMountPath == "" {
		return nil, errors.New("vault mount path cannot be empty")
	}

	if log == nil {
		return nil, errors.New("log cannot be nil")
	}

	if metricSink == nil {
		return nil, errors.New("metric sink cannot be nil")
	}

	fetcher := &AwsVaultStsTokenFetcher{
		vault: vault,

		vaultStsEndpoint:  path.Join(vaultMountPath, "sts", iamRole),
		vaultRoleEndpoint: path.Join(vaultMountPath, "roles", iamRole),

		metricSink: metricSink,
	}
	fetcher.log = log.With(zap.String("fetcher", fetcher.String()))

	return fetcher, nil
}

func (a *AwsVaultStsTokenFetcher) String() string {
	return "aws-sts-token-vault"
}

func (a *AwsVaultStsTokenFetcher) Fetch(ctx context.Context) (creds *cache.ExpiringValue[*AwsCredentials], err error) {
	fetchSpan, ctx := tracer.StartSpanFromContext(ctx, "AwsVaultStsTokenFetcher.Fetch")

	defer func() {
		fetchSpan.Finish(tracer.WithError(err))

		statusLabel := labelSuccess
		if err != nil {
			statusLabel = labelFail
		}

		labels := []metrics.Label{labelAwsProvider, labelVaultMethod, statusLabel}
		a.metricSink.IncrCounterWithLabels(statsdCloudCredRequest, 1, labels)
	}()

	role, err := a.lookupRole(ctx)
	if err != nil {
		return nil, err
	}

	// The deprecated AWS boto library only supports a format of "%Y-%m-%dT%H:%M:%SZ"
	// while the newer boto3 library appears to be more robust and support this and a
	// datetime with milliseconds. Therefore, fallback to using the older format.
	// See https://github.com/boto/boto/issues/3771
	lastUpdated := timeNow().Truncate(time.Second).UTC()
	secret, err := a.vault.ReadWithData(ctx, a.vaultStsEndpoint, map[string][]string{
		"role_arn": {role.arn},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New("unable to correctly read secret from Vault")
	}

	var decodedSecret struct {
		AccessKey     string `mapstructure:"access_key"`
		SecretKey     string `mapstructure:"secret_key"`
		SecurityToken string `mapstructure:"security_token"`
	}

	err = mapstructure.Decode(secret.Data, &decodedSecret)
	if err != nil {
		return nil, fmt.Errorf("error decoding data from Vault: %w", err)
	}

	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential TTL: %w", err)
	}

	if ttl == 0 {
		if secret.LeaseDuration > 0 {
			ttl = time.Second * time.Duration(secret.LeaseDuration)
		} else {
			a.log.Warn("credential TTL is zero, using default", zap.Duration("default", defaultAwsCredTTL))
			ttl = defaultAwsCredTTL
		}
	}

	result := &AwsCredentials{
		AccessKeyID:     decodedSecret.AccessKey,
		Code:            "Success",
		Expiration:      lastUpdated.Add(ttl),
		LastUpdated:     lastUpdated,
		SecretAccessKey: decodedSecret.SecretKey,
		Token:           decodedSecret.SecurityToken,
		Type:            "AWS-HMAC",
	}

	return &cache.ExpiringValue[*AwsCredentials]{
		Value:     result,
		ExpiresAt: result.Expiration,
	}, nil
}

// lookupRole will look up the Vault AWS role by the Vault name. Only a single role ARN can be configured with
// Attaché. Therefore, a role configuration without exactly 1 AWS role ARN will result in an error.
// The return value of this is memoized as it should never change during the Attaché lifecycle.
func (a *AwsVaultStsTokenFetcher) lookupRole(ctx context.Context) (*role, error) {
	if a.awsRole != nil {
		return a.awsRole, nil
	}

	a.lookupRoleMutex.Lock()
	defer a.lookupRoleMutex.Unlock()

	if a.awsRole != nil {
		return a.awsRole, nil
	}

	secret, err := a.vault.Read(ctx, a.vaultRoleEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to read path %q: %w", a.vaultRoleEndpoint, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, newRoleDoesNotExistError(a.vaultRoleEndpoint)
	}

	var response struct {
		RoleArns []string `mapstructure:"role_arns"`
	}

	err = mapstructure.Decode(secret.Data, &response)
	if err != nil {
		return nil, fmt.Errorf("unable to decode Vault response: %w", err)
	}

	if response.RoleArns == nil || len(response.RoleArns) == 0 {
		return nil, errors.New("vault role must have at least one role_arn defined")
	}

	if len(response.RoleArns) > 1 {
		return nil, errors.New("cannot have multiple role_arns defined for a Vault role")
	}

	roleArn := response.RoleArns[0]

	matches := awsRoleRegex.FindSubmatch([]byte(roleArn))
	if matches == nil || len(matches) < 1 {
		return nil, fmt.Errorf("unable to extract role from role ARN: %s", roleArn)
	}

	roleName := string(matches[1])
	a.awsRole = &role{name: roleName, arn: roleArn}

	return a.awsRole, nil
}

// InstanceIdentifier provides an instance identity document
type InstanceIdentifier interface {
	GetInstanceIdentity(context.Context) (interface{}, error)
}

// NewAwsInstanceIdentifier builds an instance identity document provider based
// on a given current cloud provider context.
func NewAwsInstanceIdentifier(provider, region, zone string) InstanceIdentifier {
	switch provider {
	case "aws":
		// use sparsely populated document if current provider is aws
		return (*staticAwsIdentifier)(&ec2imds.InstanceIdentityDocument{
			Region:           region,
			AvailabilityZone: zone,
		})
	default:
		// use zero-valued document if current provider is not aws
		return (*staticAwsIdentifier)(&ec2imds.InstanceIdentityDocument{})
	}
}

type staticAwsIdentifier ec2imds.InstanceIdentityDocument

func (i *staticAwsIdentifier) GetInstanceIdentity(_ context.Context) (interface{}, error) {
	return (*ec2imds.InstanceIdentityDocument)(i), nil
}
