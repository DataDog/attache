package imds

import (
	"context"
	"testing"

	"github.com/DataDog/attache/internal/cache"
	"github.com/DataDog/attache/internal/vault"
	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func Test_functionName(t *testing.T) {
	v, err := vault.NewClient(vault.DefaultConfig())
	require.NoError(t, err)

	fetcher, err := NewVaultAwsStsTokenFetcher(v, "role", "mount", zaptest.NewLogger(t), &metrics.BlackholeSink{})
	require.NoError(t, err)

	p, err := Aws(context.Background(), zaptest.NewLogger(t), false, &metrics.BlackholeSink{}, fetcher, fetcher, &staticAwsIdentifier{}, cache.NewPercentageRemainingRefreshAt(1, 0))
	require.NoError(t, err)

	tests := map[string]struct {
		handlerFunc handlerFunc
		want        string
	}{
		"provider function": {
			handlerFunc: p.handleSecurityCredentials,
			want:        "handleSecurityCredentials",
		},
		"nil": {
			handlerFunc: nil,
			want:        "",
		},
	}
	for tn, tt := range tests {
		t.Run(tn, func(t *testing.T) {
			if got := functionName(tt.handlerFunc); got != tt.want {
				t.Errorf("functionName() = %v, want %v", got, tt.want)
			}
		})
	}
}
