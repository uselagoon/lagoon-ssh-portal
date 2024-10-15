package cache

import (
	"sync"
	"time"
)

type mapValue[T any] struct {
	data   T
	expiry time.Time
}

// Map is a generic, thread-safe, in-memory cache map that stores a key-value
// pairs with a TTL, after which the cache expires.
type Map[K comparable, V any] struct {
	data map[K]mapValue[V]
	ttl  time.Duration
	mu   sync.Mutex
}

// MapOption is a functional option argument to NewCache().
type MapOption[K comparable, V any] func(*Map[K, V])

// MapWithTTL sets the the Cache time-to-live to ttl.
func MapWithTTL[K comparable, V any](ttl time.Duration) MapOption[K, V] {
	return func(c *Map[K, V]) {
		c.ttl = ttl
	}
}

// NewMap instantiates a Map for key type K and value type V with a default TTL
// of 1 minute.
func NewMap[K comparable, V any](options ...MapOption[K, V]) *Map[K, V] {
	c := Map[K, V]{
		data: map[K]mapValue[V]{},
		ttl:  defaultTTL,
	}
	for _, option := range options {
		option(&c)
	}
	return &c
}

// Set updates the value in the cache and sets the expiry to now+TTL.
func (c *Map[K, V]) Set(key K, data V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = mapValue[V]{
		data:   data,
		expiry: time.Now().Add(c.ttl),
	}
}

// Get retrieves the value from the cache. If the value doesn't exist in the
// cache, or if the cache has expired, the second return value will be false.
func (c *Map[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero mapValue[V]
	value, ok := c.data[key]
	if !ok {
		return zero.data, false
	}
	if time.Now().After(value.expiry) {
		delete(c.data, key)
		return zero.data, false
	}
	return value.data, true
}
