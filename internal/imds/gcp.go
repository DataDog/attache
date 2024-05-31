package imds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/retry"
	"github.com/DataDog/attache/internal/vault"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-metrics"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
	muxt "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	labelGcpProvider = metrics.Label{Name: "provider", Value: "gcp"}
)

// GcpServiceAccountInfoGetter returns data about the configured GCP IMDS service account.
// This meant to be temporary and will be replaced once the static data from is passed
// directly to the GcpProvider.
type GcpServiceAccountInfoGetter interface {
	lookupServiceAccount(ctx context.Context) (string, error)
	getProjectID(ctx context.Context) (string, error)
	getProjectNumber(ctx context.Context) (string, error)
}

// GcpProvider implements the GCP Metadata Service backed by Vault.
type GcpProvider struct {
	maintainer           *cache.Maintainer[*GcpCredentials]
	serviceAccountGetter GcpServiceAccountInfoGetter
}

// saProjectRegex is the regex for returning the project-id from the ServiceAccount email.
var saProjectRegex = regexp.MustCompile(`^.+@(.+)\.iam\.gserviceaccount\.com$`)

// Gcp returns a new GcpProvider.
func Gcp(ctx context.Context, log *zap.Logger,
	metricSink metrics.MetricSink,
	tokenFetcher cache.Fetcher[*GcpCredentials],
	serviceAccountInfoGetter GcpServiceAccountInfoGetter,
	refreshFunc cache.RefreshAtFunc, retryOpts ...retry.Option,
) (*GcpProvider, error) {
	if ctx == nil {
		return nil, errors.New("context cannote be nil")
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

	if tokenFetcher == nil {
		return nil, errors.New("token fetcher cannot be nil")
	}

	if serviceAccountInfoGetter == nil {
		return nil, errors.New("service account info getter cannot be nil")
	}

	maintainer := cache.NewMaintainer[*GcpCredentials](
		tokenFetcher,
		refreshFunc,
		cache.WithLogger(log.Named("token maintainer")),
		cache.WithMetricsSink(metricSink),
		cache.WithRetryOptions(retryOpts),
	)

	return &GcpProvider{
		maintainer:           maintainer,
		serviceAccountGetter: serviceAccountInfoGetter,
	}, nil
}

// Name returns the provider's logical name.
func (p *GcpProvider) Name() string {
	return "gcp"
}

// RegisterHandlers registers all HTTP handlers for the GCP provider.
func (p *GcpProvider) RegisterHandlers(router *muxt.Router, handlerFactory *HandlerFactory) error {
	pingHandle := metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handlePing))

	router.Handle("/", pingHandle)
	router.Handle("/computeMetadata/", pingHandle)
	router.Handle("/computeMetadata/v1/", pingHandle)
	router.Handle("/computeMetadata/v1/instance/", pingHandle)

	router.Handle("/computeMetadata/v1/instance/service-accounts/",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleServiceAccounts)))
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleServiceAccount)))
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/token",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleToken)))
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/email",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleEmail)))
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/identity",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleIdentity)))
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}/scopes",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleScopes)))

	// ideally handled by upstream proxy
	router.Handle("/computeMetadata/v1/project/project-id",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleProjectID)))
	router.Handle("/computeMetadata/v1/project/numeric-project-id",
		metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleNumericProjectID)))

	// Currently not supported GCE Metadata Service endpoints
	notImplemented := handlerFactory.CreateHTTPHandler(p.Name(), p.handleNotImplemented)
	router.Handle("/computeMetadata/v1/instance/attributes/", notImplemented)
	router.Handle("/computeMetadata/v1/instance/attributes/{attribute:[^/]+}", notImplemented)
	router.Handle("/computeMetadata/v1/project/", notImplemented)
	router.Handle("/computeMetadata/v1/instance/id", notImplemented)
	router.Handle("/computeMetadata/v1/instance/zone", notImplemented)
	router.Handle("/computeMetadata/v1/instance/cpu-platform", notImplemented)

	// Support for gsutil
	slashRedirect := metadataFlavorHeaderVerifier(handlerFactory.CreateHTTPHandler(p.Name(), p.handleSlashRedirect))
	router.Handle("/computeMetadata", slashRedirect)
	router.Handle("/computeMetadata/v1", slashRedirect)
	router.Handle("/computeMetadata/v1/instance/service-accounts", slashRedirect)
	router.Handle("/computeMetadata/v1/instance/service-accounts/{serviceAccount:[^/]+}", slashRedirect)
	router.Handle("/computeMetadata/v1/project", slashRedirect)
	router.Handle("/computeMetadata/v1/instance", slashRedirect)
	router.Handle("/computeMetadata/v1/instance/attributes", slashRedirect)

	return nil
}

func (p *GcpProvider) handleProjectID(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	projectID, err := p.serviceAccountGetter.getProjectID(r.Context())
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(projectID))

	return err
}

func (p *GcpProvider) handleNumericProjectID(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	projectNumber, err := p.serviceAccountGetter.getProjectNumber(r.Context())
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(projectNumber))

	return err
}

func (p *GcpProvider) handleSlashRedirect(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	http.Redirect(w, r, "http://"+r.Host+r.URL.Path+"/", http.StatusMovedPermanently)

	return nil
}

func (p *GcpProvider) handleToken(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	serviceAccountEmail, err := p.serviceAccountGetter.lookupServiceAccount(r.Context())
	if err != nil {
		return fmt.Errorf("error looking up service account: %w", err)
	}

	if err = p.verifyServiceAccount(r, serviceAccountEmail); err != nil {
		return fmt.Errorf("service account error: %w", err)
	}

	// Pass background context to ignore cancellation signal and cache
	// credentials in case of low timeout on imds client. Retried requests
	// by client should eventually succeed once cached credentials are
	// populated.
	//
	// The parent span is copied to include upstream calls in any trace.
	reqSpan, _ := tracer.SpanFromContext(r.Context())
	reqCtx := tracer.ContextWithSpan(context.Background(), reqSpan)

	gcpCreds, err := p.maintainer.Get(reqCtx)
	if err != nil {
		return err
	}

	if r.Context().Err() != nil {
		return r.Context().Err()
	}

	credsResp := gcpCredentialsResponse{
		AccessToken: gcpCreds.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(gcpCreds.expires()).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(credsResp)
}

type gcpCredentialsResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (p *GcpProvider) handlePing(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)

	// some sdks (the official typescript one in particular) expect a non-empty
	// body in the response.
	_, err := w.Write([]byte("ok"))

	return err
}

func (p *GcpProvider) handleServiceAccounts(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	serviceAccountEmail, err := p.serviceAccountGetter.lookupServiceAccount(r.Context())
	if err != nil {
		return fmt.Errorf("error looking up service account: %w", err)
	}
	_, err = w.Write([]byte(fmt.Sprintf("default/\n%s/\n", serviceAccountEmail)))

	return err
}

func (p *GcpProvider) handleServiceAccount(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	serviceAccountEmail, err := p.serviceAccountGetter.lookupServiceAccount(r.Context())
	if err != nil {
		return fmt.Errorf("error looking up service account: %w", err)
	}

	if err = p.verifyServiceAccount(r, serviceAccountEmail); err != nil {
		return fmt.Errorf("service account error: %w", err)
	}

	result := &struct {
		Aliases []string `json:"aliases"`
		Email   string   `json:"email"`
		Scopes  []string `json:"scopes"`
	}{
		Aliases: []string{"default"},
		Email:   serviceAccountEmail,
		Scopes:  []string{"https://www.googleapis.com/auth/cloud-platform"},
	}

	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(result)
}

func (p *GcpProvider) handleEmail(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	serviceAccountEmail, err := p.serviceAccountGetter.lookupServiceAccount(r.Context())
	if err != nil {
		return fmt.Errorf("error looking up service account: %w", err)
	}

	if err = p.verifyServiceAccount(r, serviceAccountEmail); err != nil {
		return fmt.Errorf("service account error: %w", err)
	}

	_, err = w.Write([]byte(serviceAccountEmail))

	return err
}

func (p *GcpProvider) handleIdentity(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	// gcloud tooling currently makes a call to retrieve an OIDC token but doesn't appear to do anything
	// with that. gcloud also ignores the 404 errors (see lib/googlecloudsdk/core/credentials/gce.py GetIdToken).
	// For now, we'll return a 404 but this is brittle. Longer term we should consider forking and pushing a
	// fix upstream for vault-plugin-secrets-gcp to support OIDC tokens (see
	// https://github.com/hashicorp/vault-plugin-secrets-gcp/issues/46).
	return HTTPError{
		code:  http.StatusNotFound,
		error: errors.New("OIDC tokens not supported"),
	}
}

func (p *GcpProvider) handleScopes(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	_, err := w.Write([]byte("https://www.googleapis.com/auth/cloud-platform\nhttps://www.googleapis.com/auth/userinfo.email\n"))

	return err
}

func (p *GcpProvider) handleNotImplemented(_ *zap.Logger, w http.ResponseWriter, r *http.Request) error {
	return HTTPError{
		code:  http.StatusNotImplemented,
		error: errors.New(http.StatusText(http.StatusNotImplemented)),
	}
}

// verifyServiceAccount verifies that the HTTP request's named path parameter matches the serviceAccountEmail.
func (p *GcpProvider) verifyServiceAccount(r *http.Request, expectedServiceAccount string) error {
	routeVars := mux.Vars(r)
	iamServiceAccount, ok := routeVars["serviceAccount"]
	if !ok {
		// should not reach here so long as route regex has a named match
		return errors.New("request did not contain a serviceAccount in path")
	}

	if iamServiceAccount != "default" && iamServiceAccount != expectedServiceAccount {
		return fmt.Errorf("service account for requested token (%v) does not match configured IAM role(%v)", iamServiceAccount, expectedServiceAccount)
	}

	return nil
}

// metadataFlavorHeaderVerifier middleware that ensures the HTTP request contains the "Metadata-Flavor: Google" header
// and ensures that the same header is set for responses.
func metadataFlavorHeaderVerifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "Missing Metadata-Flavor:Google header", http.StatusForbidden)

			return
		}

		next.ServeHTTP(w, r)
	})
}

type GcpCredentials struct {
	Token            string `mapstructure:"token"`
	ExpiresAtSeconds int64  `mapstructure:"expires_at_seconds"`
}

func (v *GcpCredentials) expires() time.Time {
	return time.Unix(v.ExpiresAtSeconds, 0)
}

type GcpVaultTokenFetcher struct {
	vault      *vault.Client
	vaultMount string

	iamRole             string
	serviceAccountEmail string
	projectIds          map[string]string

	vaultPath              string
	vaultPathLastCheckTime time.Time
	impersonatedVaultPath  bool

	pathLookupMutex           sync.Mutex
	serviceAccountLookupMutex sync.Mutex

	log        *zap.Logger
	metricSink metrics.MetricSink
}

func NewGcpVaultTokenFetcher(vault *vault.Client,
	iamRole, vaultMountPath string,
	projectIds map[string]string,
	log *zap.Logger,
	metricSink metrics.MetricSink,
) (*GcpVaultTokenFetcher, error) {
	if log == nil {
		return nil, errors.New("log cannot be nil")
	}

	if metricSink == nil {
		return nil, errors.New("metricSink cannot be nil")
	}

	if vault == nil {
		return nil, errors.New("vault client cannot be nil")
	}

	if iamRole == "" {
		return nil, errors.New("iam role cannot be empty")
	}

	if vaultMountPath == "" {
		return nil, errors.New("vault mount path cannot be empty")
	}

	return &GcpVaultTokenFetcher{
		iamRole:    iamRole,
		projectIds: projectIds,
		vault:      vault,
		vaultMount: strings.TrimSuffix(vaultMountPath, "/"),

		log:        log,
		metricSink: metricSink,
	}, nil
}

func (g *GcpVaultTokenFetcher) String() string {
	return "gcp-token-vault"
}

func (g *GcpVaultTokenFetcher) Fetch(ctx context.Context) (creds *cache.ExpiringValue[*GcpCredentials], err error) {
	fetchSpan, ctx := tracer.StartSpanFromContext(ctx, "GcpVaultTokenFetcher.Fetch")

	defer func() {
		fetchSpan.Finish(tracer.WithError(err))

		statusLabel := labelSuccess
		if err != nil {
			statusLabel = labelFail
		}

		labels := []metrics.Label{labelGcpProvider, labelVaultMethod, statusLabel}
		g.metricSink.IncrCounterWithLabels(statsdCloudCredRequest, 1, labels)
	}()

	p, err := g.determineVaultPath(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := g.vault.Read(ctx, path.Join(p, "token"))
	if err != nil {
		return nil, fmt.Errorf("failed to read token from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New("unable to correctly read secret from Vault")
	}

	var gcpToken *GcpCredentials
	err = mapstructure.Decode(secret.Data, &gcpToken)
	if err != nil {
		return nil, err
	}

	return &cache.ExpiringValue[*GcpCredentials]{
		Value:     gcpToken,
		ExpiresAt: gcpToken.expires(),
	}, nil
}

func (g *GcpVaultTokenFetcher) determineVaultPath(ctx context.Context) (string, error) {
	recheckFrequency := 30 * time.Minute
	durationSinceLastChecked := time.Since(g.vaultPathLastCheckTime)
	if g.vaultPath != "" && (g.impersonatedVaultPath || durationSinceLastChecked < recheckFrequency) {
		return g.vaultPath, nil
	}

	g.pathLookupMutex.Lock()
	defer g.pathLookupMutex.Unlock()

	durationSinceLastChecked = time.Since(g.vaultPathLastCheckTime)
	if g.vaultPath != "" && (g.impersonatedVaultPath || durationSinceLastChecked < recheckFrequency) {
		return g.vaultPath, nil
	}

	var err error

	impersonatedAccountPath := path.Join(g.vaultMount, "impersonated-account", g.iamRole)
	secret, err := g.vault.Read(ctx, impersonatedAccountPath)
	if err != nil {
		return "", fmt.Errorf("failed to read impersonated-account from Vault: %w", err)
	}

	if secret != nil {
		g.vaultPath = impersonatedAccountPath
		g.impersonatedVaultPath = true
		g.vaultPathLastCheckTime = time.Now()

		return g.vaultPath, nil
	}

	rolesetPath := path.Join(g.vaultMount, "roleset", g.iamRole)
	secret, err = g.vault.Read(ctx, rolesetPath)
	if err != nil {
		return "", fmt.Errorf("failed to read roleset from Vault: %w", err)
	}

	if secret != nil {
		g.vaultPath = rolesetPath
		g.vaultPathLastCheckTime = time.Now()

		return g.vaultPath, nil
	}

	return "", fmt.Errorf("%w: could not find impersonated account or rolepath, tried %q and %q", newRoleDoesNotExistError(g.iamRole), impersonatedAccountPath, rolesetPath)
}

// lookupServiceAccount will lookup a service account for the configured GcpProvider iamRole.
// The return value of this is memoized as it should never change during the Attaché lifecycle.
func (g *GcpVaultTokenFetcher) lookupServiceAccount(ctx context.Context) (string, error) {
	if g.serviceAccountEmail != "" {
		return g.serviceAccountEmail, nil
	}

	g.serviceAccountLookupMutex.Lock()
	defer g.serviceAccountLookupMutex.Unlock()

	if g.serviceAccountEmail != "" {
		return g.serviceAccountEmail, nil
	}

	p, err := g.determineVaultPath(ctx)
	if err != nil {
		return "", err
	}

	secret, err := g.vault.Read(ctx, p)
	if err != nil {
		return "", fmt.Errorf("failed to read service account from Vault: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", newRoleDoesNotExistError(p)
	}

	g.serviceAccountEmail = fmt.Sprintf("%v", secret.Data["service_account_email"])

	return g.serviceAccountEmail, nil
}

func (g *GcpVaultTokenFetcher) getProjectID(ctx context.Context) (string, error) {
	serviceAccountEmail, err := g.lookupServiceAccount(ctx)
	if err != nil {
		return "", err
	}

	matches := saProjectRegex.FindSubmatch([]byte(serviceAccountEmail))
	if matches == nil || len(matches) < 1 {
		return "", errors.New("error extracting project ID from service account email")
	}

	return string(matches[1]), nil
}

func (g *GcpVaultTokenFetcher) getProjectNumber(_ context.Context) (string, error) {
	projectNumber, ok := g.projectIds[g.vaultMount]
	if !ok {
		return "", errors.New("numeric project ID not configured for GCP")
	}

	return projectNumber, nil
}
