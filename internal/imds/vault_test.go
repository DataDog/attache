package imds

import (
	"os"
	"sync"
	"testing"

	ddvault "github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-hclog"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/vault/seal"
	"github.com/stretchr/testify/require"
)

var wg sync.WaitGroup

func newVaultCluster(t *testing.T) *ddvault.Client {
	t.Helper()
	log := logging.NewVaultLogger(hclog.Warn)
	coreConfig := &vault.CoreConfig{}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		Logger:      log,
		NumCores:    1,
		// SealFunc doesn't need to be set for all of this to work, but in order to avoid
		// 'no seal config found, can't determine if legacy or new-style shamir' being logged
		// out multiple times per test, we explicitly configure the test seal here
		SealFunc: func() vault.Seal {
			return vault.NewTestSeal(t, &seal.TestSealOpts{
				StoredKeys: seal.StoredKeysSupportedShamirRoot,
			})
		},
	})
	cluster.Start()
	vault.TestWaitActive(t, cluster.Cores[0].Core)
	core := cluster.Cores[0]
	client := core.Client

	require.NoError(t, os.Setenv("VAULT_ADDR", client.Address()))
	require.NoError(t, os.Setenv("VAULT_TOKEN", client.Token()))

	config := ddvault.DefaultConfig()

	// we have two options when testing: directly use the core client from the
	// test vault cluster, which will have all the right CA Certs configured
	// _or_ disable TLS verification if we need to configure out own client,
	// which for these tests of our client configuring paths, we need to do
	config.Insecure = true

	c, err := ddvault.NewClient(config)
	require.NoError(t, err)

	t.Cleanup(func() {
		// this call currently includes a needless 1 second time.Sleep call,
		// which may be an issue as we keep adding test cases, so we do the cleanup
		// in its own goroutine and register with a package level wait group.
		wg.Add(1)
		go func() {
			cluster.Cleanup()
			wg.Done()
		}()
	})

	return c
}
