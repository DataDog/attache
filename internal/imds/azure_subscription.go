package imds

import (
	"context"
	"errors"
	"path"
	"sync"
	"time"

	"github.com/DataDog/attache/internal/vault"
	"github.com/mitchellh/mapstructure"
)

// AzureSubscriptionIDGetter returns the Azure subscription ID for IMDS
type AzureSubscriptionIDGetter interface {
	getSubscriptionID(ctx context.Context) (string, error)
}

// azureStaticSubscriptionIDGetter is an AzureSubscriptionIDGetter that always returns a static value
type azureStaticSubscriptionIDGetter struct {
	subscriptionID string
}

func NewAzureStaticSubscriptionIDGetter(subscriptionID string) AzureSubscriptionIDGetter {
	return &azureStaticSubscriptionIDGetter{
		subscriptionID: subscriptionID,
	}
}

func (g *azureStaticSubscriptionIDGetter) getSubscriptionID(ctx context.Context) (string, error) {
	return g.subscriptionID, nil
}

// azureVaultSubscriptionIDGetter is an AzureSubscriptionIDGetter that fetches the subscription ID from Vault
type azureVaultSubscriptionIDGetter struct {
	vault               *vault.Client
	vaultConfigEndpoint string

	subscription           string
	subscriptionExpiration time.Time
	subscriptionMutex      sync.RWMutex
}

func NewAzureVaultSubscriptionIDGetter(vault *vault.Client, vaultMountPath string) AzureSubscriptionIDGetter {
	return &azureVaultSubscriptionIDGetter{
		vault:               vault,
		vaultConfigEndpoint: path.Join(vaultMountPath, "config"),
	}
}

type vaultAzureConfig struct {
	TenantID       string `mapstructure:"tenant_id"`
	SubscriptionID string `mapstructure:"subscription_id"`
	ClientID       string `mapstructure:"client_id"`
	Environment    string `mapstructure:"environment"`
}

// getSubscriptionID fetches the Azure subscription ID from Vault.
func (g *azureVaultSubscriptionIDGetter) getSubscriptionID(ctx context.Context) (string, error) {
	g.subscriptionMutex.RLock()
	curSubscription := g.subscription
	curSubscriptionExpiry := g.subscriptionExpiration
	g.subscriptionMutex.RUnlock()
	if curSubscription != "" && curSubscriptionExpiry.After(timeNow()) {
		return curSubscription, nil
	}

	g.subscriptionMutex.Lock()
	defer g.subscriptionMutex.Unlock()
	if g.subscription != "" && g.subscriptionExpiration.After(timeNow()) {
		return g.subscription, nil
	}

	secret, err := g.vault.Read(ctx, g.vaultConfigEndpoint)
	if err != nil {
		return "", err
	}

	if secret == nil || secret.Data == nil {
		return "", errors.New("vault azure config is empty")
	}

	var c vaultAzureConfig
	if err = mapstructure.Decode(secret.Data, &c); err != nil {
		return "", err
	}

	g.subscription = c.SubscriptionID
	g.subscriptionExpiration = timeNow().Add(5 * time.Minute)

	return g.subscription, nil
}
