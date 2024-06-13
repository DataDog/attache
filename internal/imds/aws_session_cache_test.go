package imds

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-metrics"
	"github.com/stretchr/testify/assert"
)

func Test_imdsSessionCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	t.Run("generate session", func(t *testing.T) {
		c := newIMDSSessionCache(ctx, &metrics.BlackholeSink{}, 3, time.Hour)

		want, _, err := c.NewSession(time.Hour)
		assert.NoError(t, err)

		have, ok := c.GetSession(want.ID)
		assert.True(t, ok)
		assert.Equal(t, want, have)
	})

	t.Run("expire session", func(t *testing.T) {
		c := newIMDSSessionCache(ctx, &metrics.BlackholeSink{}, 3, time.Hour)

		before, after := time.Now(), time.Now().Add(1*time.Hour)
		timeNow = func() time.Time { return before }
		defer func() { timeNow = time.Now }()

		s, _, err := c.NewSession(time.Hour)
		assert.NoError(t, err)

		have, ok := c.GetSession(s.ID)
		assert.True(t, ok)
		assert.Equal(t, s, have)
		assert.Equal(t, 1, c.list.Len())

		// advance time past expiry
		timeNow = func() time.Time { return after }

		// not gettable, not yet evicted
		have, ok = c.GetSession(s.ID)
		assert.False(t, ok)
		assert.Nil(t, have)
		assert.Equal(t, 1, c.list.Len())

		c.evictExpired()

		// evicted
		have, ok = c.GetSession(s.ID)
		assert.False(t, ok)
		assert.Nil(t, have)
		assert.Equal(t, 0, c.list.Len())
	})

	t.Run("lru overflow eviction", func(t *testing.T) {
		c := newIMDSSessionCache(ctx, &metrics.BlackholeSink{}, 2, time.Hour)

		s1, evicted, err := c.NewSession(time.Hour)
		assert.NoError(t, err)
		assert.False(t, evicted)

		s2, evicted, err := c.NewSession(time.Hour)
		assert.NoError(t, err)
		assert.False(t, evicted)

		// add s3, evict s1
		s3, evicted, err := c.NewSession(time.Hour)
		assert.NoError(t, err)
		assert.True(t, evicted)

		_, ok := c.GetSession(s1.ID)
		assert.False(t, ok)
		_, ok = c.GetSession(s3.ID)
		assert.True(t, ok)
		_, ok = c.GetSession(s2.ID)
		assert.True(t, ok)

		// add s4, evict s3
		s4, evicted, err := c.NewSession(time.Hour)
		assert.NoError(t, err)
		assert.True(t, evicted)

		_, ok = c.GetSession(s3.ID)
		assert.False(t, ok)
		_, ok = c.GetSession(s2.ID)
		assert.True(t, ok)
		_, ok = c.GetSession(s4.ID)
		assert.True(t, ok)
	})
}
