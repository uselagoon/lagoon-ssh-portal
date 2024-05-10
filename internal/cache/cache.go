// Package cache implements a generic, thread-safe, in-memory cache.
package cache

import (
	"sync"
	"time"
)

const (
	defaultTTL = time.Minute
)

// Cache is a generic, thread-safe, in-memory cache that stores a value with a
// TTL, after which the cache expires.
type Cache[T any] struct {
	data   T
	expiry time.Time
	ttl    time.Duration
	mu     sync.Mutex
}

// Option is a functional option argument to NewCache().
type Option[T any] func(*Cache[T])

// WithTTL sets the the Cache time-to-live to ttl.
func WithTTL[T any](ttl time.Duration) Option[T] {
	return func(c *Cache[T]) {
		c.ttl = ttl
	}
}

// NewCache instantiates a Cache for type T with a default TTL of 1 minute.
func NewCache[T any](options ...Option[T]) *Cache[T] {
	c := Cache[T]{
		ttl: defaultTTL,
	}
	for _, option := range options {
		option(&c)
	}
	return &c
}

// Set updates the value in the cache and sets the expiry to now+TTL.
func (c *Cache[T]) Set(value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = value
	c.expiry = time.Now().Add(c.ttl)
}

// Get retrieves the value from the cache. If cache has expired, the second
// return value will be false.
func (c *Cache[T]) Get() (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.expiry) {
		var zero T
		return zero, false
	}
	return c.data, true
}
