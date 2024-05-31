package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/attache/internal/imds"
	"github.com/DataDog/attache/internal/server"
	"github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"go.uber.org/zap"
)

func main() {
	fmt.Println("attaché")

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	log, err := zap.NewDevelopment()
	if err != nil {
		fmt.Printf("could not initialize logger: %v\n", err)
		os.Exit(11)
	}

	// This configuration is usually injected by the same admission webhook injecting the sidecar container
	config := imds.Config{
		IamRole:           "frostbite-falls_bullwinkle",
		GcpVaultMountPath: "cloud-iam/gcp/datadog-sandbox",
		AwsVaultMountPath: "cloud-iam/aws/601427279990",
		ServerConfig: server.Config{
			BindAddress: "127.0.0.1:8080",
		},
		GcpProjectIds: map[string]string{
			"datadog-sandbox": "958371799887",
		},
	}

	vConfig := vault.DefaultConfig()
	v, err := vault.NewClient(vConfig)

	server, closeFunc, err := imds.NewServer(context.Background(), &imds.MetadataServerConfig{
		CloudiamConf:  config,
		DDVaultClient: v,
		MetricSink:    &metrics.BlackholeSink{},
		Log:           log,
	})
	if err != nil {
		fmt.Printf("could not initialize imds server: %v\n", err)
		os.Exit(12)
	}
	defer closeFunc()

	errs := make(chan error, 1)
	shutdown := server.Run(errs)
	defer shutdown()

	for {
		select {
		case err := <-errs:
			log.Error("attaché imds server error", zap.Error(err))
			os.Exit(58)
		case sig := <-osSignals:
			log.Info("received os signal", zap.Stringer("os.Signal", sig))
			return
		}
	}
}
