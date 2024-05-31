package cache

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeKey(parts []string) string {
	return strings.Join(parts, ".")
}

type mockValue struct {
	value  float32
	labels []metrics.Label
}

type mockSink struct {
	gauges map[string]mockValue
}

func newMockSink() mockSink {
	return mockSink{
		gauges: make(map[string]mockValue),
	}
}

// A Gauge should retain the last value it is set to
func (m *mockSink) SetGauge(key []string, val float32) {
	m.gauges[makeKey(key)] = mockValue{val, nil}
}
func (m *mockSink) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	m.gauges[makeKey(key)] = mockValue{val, labels}
}

// Should emit a Key/Value pair for each call
func (m *mockSink) EmitKey(key []string, val float32) {}

// Counters should accumulate values
func (m *mockSink) IncrCounter(key []string, val float32)                                   {}
func (m *mockSink) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {}

// Samples are for timing information, where quantiles are used
func (m *mockSink) AddSample(key []string, val float32)                                   {}
func (m *mockSink) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {}

func newSetTestReporter(maintaining bool, refreshAt time.Time, expiresAt time.Time) *metricsReporter {
	return &metricsReporter{
		isMaintaining: &maintaining,
		refreshAt:     refreshAt,
		expiresAt:     expiresAt,
	}
}

func TestReporter(t *testing.T) {
	refreshAt := time.Now().Add(5 * time.Hour)
	untilRefreshAt := float32(5 * time.Hour / time.Second)
	expiresAt := time.Now().Add(5 * time.Hour)
	untilExpiresAt := float32(5 * time.Hour / time.Second)

	for name, test := range map[string]struct {
		reporter        *metricsReporter
		expectedMetrics map[string]mockValue
	}{
		"reporter initialized but not maintaining": {
			reporter: &metricsReporter{},
			expectedMetrics: map[string]mockValue{
				makeKey(statsdCacheMaintainerState): {1, []metrics.Label{statsdCacheMaintainerInit}},
			},
		},
		"reporter set to maintaining but other values unset": {
			reporter: newSetTestReporter(true, time.Time{}, time.Time{}),
			expectedMetrics: map[string]mockValue{
				makeKey(statsdCacheMaintainerState):         {1, []metrics.Label{statsdCacheMaintainerRunning}},
				makeKey(statsdCacheMaintainerExpirationTTL): {0, []metrics.Label{statsdCacheMaintainerRunning}},
				makeKey(statsdCacheMaintainerNextRefresh):   {0, []metrics.Label{statsdCacheMaintainerRunning}},
			},
		},
		"reporter set to maintaining and other values set": {
			reporter: newSetTestReporter(true, refreshAt, expiresAt),
			expectedMetrics: map[string]mockValue{
				makeKey(statsdCacheMaintainerState):         {1, []metrics.Label{statsdCacheMaintainerRunning}},
				makeKey(statsdCacheMaintainerExpirationTTL): {untilExpiresAt, []metrics.Label{statsdCacheMaintainerRunning}},
				makeKey(statsdCacheMaintainerNextRefresh):   {untilRefreshAt, []metrics.Label{statsdCacheMaintainerRunning}},
			},
		},
		"reporter set to not maintaining and other values set": {
			reporter: newSetTestReporter(false, refreshAt, expiresAt),
			expectedMetrics: map[string]mockValue{
				makeKey(statsdCacheMaintainerState):         {1, []metrics.Label{statsdCacheMaintainerStopped}},
				makeKey(statsdCacheMaintainerExpirationTTL): {untilExpiresAt, []metrics.Label{statsdCacheMaintainerStopped}},
				makeKey(statsdCacheMaintainerNextRefresh):   {untilRefreshAt, []metrics.Label{statsdCacheMaintainerStopped}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockSink := newMockSink()
			test.reporter.report(&mockSink, []metrics.Label{{Name: "mylabel", Value: "myvalue"}})

			assert.Len(t, mockSink.gauges, len(test.expectedMetrics))
			for metricName, metricValue := range test.expectedMetrics {
				if assert.Contains(t, mockSink.gauges, metricName) {
					setMetricValue := mockSink.gauges[metricName]
					// Tolerate a one second error margin
					assert.InDelta(t, metricValue.value, setMetricValue.value, 1)
					for _, label := range metricValue.labels {
						assert.Contains(t, setMetricValue.labels, label)
					}
					// Ensure user provided labels are properly kept
					assert.Contains(t, setMetricValue.labels, metrics.Label{Name: "mylabel", Value: "myvalue"})
				}
			}
		})
	}

	t.Run("maintaining set is never revoked", func(t *testing.T) {
		reporter := metricsReporter{}
		assert.Nil(t, reporter.isMaintaining)

		reporter.setMaintaining(true)
		require.NotNil(t, reporter.isMaintaining)
		assert.True(t, *reporter.isMaintaining)

		reporter.setMaintaining(false)
		require.NotNil(t, reporter.isMaintaining)
		assert.False(t, *reporter.isMaintaining)

		reporter.setMaintaining(true)
		require.NotNil(t, reporter.isMaintaining)
		assert.True(t, *reporter.isMaintaining)
	})
}
