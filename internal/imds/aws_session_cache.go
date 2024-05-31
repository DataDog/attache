package imds

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/hashicorp/go-metrics"
)

var (
	statsdIMDSSessionActive = []string{"imds", "active_sessions"}
	statsdIMDSSessionCreate = []string{"imds", "sessions_create"}
	statsdIMDSSessionRevoke = []string{"imds", "sessions_revoke"}
	imdsSessionExpired      = []metrics.Label{{Name: "reason", Value: "expired"}}
	imdsSessionOverflow     = []metrics.Label{{Name: "reason", Value: "overflow"}}
)

const (
	maxAwsEC2MetadataTokens = 5000
)

type imdsSessionCache struct {
	metricSink metrics.MetricSink
	sess       map[string]*imdsSession
	list       *list.List
	max        int
	mu         sync.Mutex
}

type imdsSession struct {
	ID      string
	Expiry  time.Time
	element *list.Element
}

func newIMDSSessionCache(ctx context.Context, metricSink metrics.MetricSink, max int, cleanup time.Duration) *imdsSessionCache {
	sc := &imdsSessionCache{
		metricSink: metricSink,
		sess:       make(map[string]*imdsSession),
		list:       list.New(),
		max:        max,
	}

	go sc.evictBackground(ctx, cleanup)

	go sc.reportMetrics(ctx)

	return sc
}

func (sc *imdsSessionCache) NewSession(ttl time.Duration) (s *imdsSession, evicted bool, err error) {
	// match encoded length of actual EC2 IMDSv2 session tokens
	byt := make([]byte, 40)
	if _, err = rand.Read(byt); err != nil {
		return
	}

	sc.metricSink.IncrCounter(statsdIMDSSessionCreate, 1.0)

	s = &imdsSession{
		ID:     base64.URLEncoding.EncodeToString(byt),
		Expiry: timeNow().Add(ttl),
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.sess[s.ID] = s
	s.element = sc.list.PushFront(s)

	if sc.list.Len() > sc.max {
		sc.evictOverflow()
		evicted = true
	}

	return
}

func (sc *imdsSessionCache) GetSession(id string) (*imdsSession, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	s, ok := sc.sess[id]
	if !ok || s.Expiry.Before(timeNow()) {
		return nil, false
	}

	sc.list.MoveToFront(s.element)

	return s, true
}

func (sc *imdsSessionCache) evictBackground(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sc.mu.Lock()
			sc.evictExpired()
			sc.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (sc *imdsSessionCache) evictOverflow() {
	for sc.list.Len() > sc.max {
		// evict least recently used
		v := sc.list.Remove(sc.list.Back())

		if s, ok := v.(*imdsSession); ok {
			delete(sc.sess, s.ID)
		}

		sc.metricSink.IncrCounterWithLabels(statsdIMDSSessionRevoke, 1.0, imdsSessionOverflow)
	}
}

func (sc *imdsSessionCache) evictExpired() {
	now := timeNow()

	for _, s := range sc.sess {
		if s.Expiry.Before(now) {
			sc.list.Remove(s.element)

			delete(sc.sess, s.ID)

			sc.metricSink.IncrCounterWithLabels(statsdIMDSSessionRevoke, 1.0, imdsSessionExpired)
		}
	}
}

func (sc *imdsSessionCache) reportMetrics(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sc.mu.Lock()
			sc.metricSink.SetGauge(statsdIMDSSessionActive, float32(sc.list.Len()))
			sc.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
