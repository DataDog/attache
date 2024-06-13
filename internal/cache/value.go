package cache

import (
	"sync"
	"time"
)

type ExpiringValue[T any] struct {
	Value     T
	ExpiresAt time.Time
}

type cachedValue[T any] struct {
	mutex sync.RWMutex
	value *ExpiringValue[T] //nolint:unused,nolintlint
}

// getValue returns the value if it has not expired
func (v *cachedValue[T]) getValue() (T, bool) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	if v.value != nil && v.value.ExpiresAt.After(time.Now()) {
		return v.value.Value, true
	}

	var empty T
	return empty, false
}

func (v *cachedValue[T]) expiresAt() time.Time {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	if v.value != nil {
		return v.value.ExpiresAt
	} else {
		return time.Time{}
	}
}

func (v *cachedValue[T]) updateValue(val *ExpiringValue[T]) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.value = val
}
