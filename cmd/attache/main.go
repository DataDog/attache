package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/attache/internal/imds"
	"github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func main() {
	fmt.Println("starting attaché")

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	log, err := zap.NewDevelopment()
	if err != nil {
		fmt.Printf("could not initialize logger: %v\n", err)
		os.Exit(11)
	}

	if len(os.Args) != 2 {
		log.Error("usage: attache <config-file>")
		os.Exit(12)
	}

	filePath := os.Args[1]
	log.Debug("loading configuration", zap.String("path", filePath))

	config := &imds.Config{}
	b, err := os.ReadFile(filePath)
	if err != nil {
		log.Error("unable to load configuration file", zap.String("path", filePath), zap.Error(err))
		os.Exit(15)
	}
	err = yaml.Unmarshal(b, config)
	if err != nil {
		log.Error("unable to parse configuration file", zap.String("path", filePath), zap.Error(err))
		os.Exit(19)
	}

	log.Debug("configuration loaded", zap.Any("configuration", config))

	vConfig := vault.DefaultConfig()
	v, err := vault.NewClient(vConfig)

	server, closeFunc, err := imds.NewServer(context.Background(), &imds.MetadataServerConfig{
		CloudiamConf:  *config,
		DDVaultClient: v,
		MetricSink:    &metrics.BlackholeSink{},
		Log:           log,
	})
	if err != nil {
		fmt.Printf("could not initialize imds server: %v\n", err)
		os.Exit(19)
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
