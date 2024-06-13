package cache

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/go-metrics"
)

type metricsReporter struct {
	mutex         sync.Mutex
	isMaintaining *bool
	refreshAt     time.Time
	expiresAt     time.Time
}

func (r *metricsReporter) setMaintaining(m bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.isMaintaining = new(bool)
	*r.isMaintaining = m
}

func (r *metricsReporter) setExpiresAt(t time.Time) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.expiresAt = t
}

func (r *metricsReporter) setRefreshAt(t time.Time) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.refreshAt = t
}

func (r *metricsReporter) run(ctx context.Context, metricSink metrics.MetricSink, tags []metrics.Label) {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			r.report(metricSink, tags)
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (r *metricsReporter) report(metricSink metrics.MetricSink, tags []metrics.Label) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// The maintainer is not yet maintaining credentials
	// Metrics are not reported to avoid setting 0
	if r.isMaintaining == nil {
		metricSink.SetGaugeWithLabels(statsdCacheMaintainerState, 1, append(tags, statsdCacheMaintainerInit))
		return
	}

	if *r.isMaintaining {
		tags = append(tags, statsdCacheMaintainerRunning)
	} else {
		tags = append(tags, statsdCacheMaintainerStopped)
	}

	ttr := float64(0)
	if !r.refreshAt.IsZero() {
		ttr = time.Until(r.refreshAt).Seconds()
		if ttr < 0 {
			ttr = -1
		}
	}

	metricSink.SetGaugeWithLabels(statsdCacheMaintainerNextRefresh, float32(ttr), tags)

	ttl := float64(0)
	if !r.expiresAt.IsZero() {
		ttl = time.Until(r.expiresAt).Seconds()
		if ttl < 0 {
			ttl = -1
		}
	}
	metricSink.SetGaugeWithLabels(statsdCacheMaintainerExpirationTTL, float32(ttl), tags)

	metricSink.SetGaugeWithLabels(statsdCacheMaintainerState, 1, tags)
}
