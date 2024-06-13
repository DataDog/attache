package imds

import (
	"context"
	"testing"

	vaultclient "github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func fromVaultClient(t *testing.T) *vaultclient.Client {
	t.Helper()

	config := vaultclient.DefaultConfig()
	config.Insecure = true

	ddClient, err := vaultclient.NewClient(config)
	require.NoError(t, err)

	return ddClient
}

func TestNewServer(t *testing.T) {
	_ = newVaultCluster(t)

	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
	config := Config{
		IamRole:             "blah",
		AwsVaultMountPath:   "aws",
		GcpVaultMountPath:   "gcp",
		AzureVaultMountPath: "azure",
	}

	server, closeFunc, err := NewServer(context.Background(), &MetadataServerConfig{
		CloudiamConf:  config,
		DDVaultClient: fromVaultClient(t),
		MetricSink:    &metrics.BlackholeSink{},
		Log:           logger,
	})
	require.NoError(t, err)
	require.NotNil(t, closeFunc)
	defer closeFunc()

	eChan := make(chan error, 1)
	shutdown := server.Run(eChan)
	defer shutdown()
}
