// Package cache implements a generic, thread-safe, in-memory cache.
package cache

import (
	"sync"
	"time"
)

const (
	defaultTTL = time.Minute
)

// Any is a generic, thread-safe, in-memory cache that stores a value with a
// TTL, after which the cache expires.
type Any[T any] struct {
	data   T
	expiry time.Time
	ttl    time.Duration
	mu     sync.Mutex
}

// AnyOption is a functional option argument to NewCache().
type AnyOption[T any] func(*Any[T])

// AnyWithTTL sets the the Cache time-to-live to ttl.
func AnyWithTTL[T any](ttl time.Duration) AnyOption[T] {
	return func(c *Any[T]) {
		c.ttl = ttl
	}
}

// NewAny instantiates an Any cache for type T with a default TTL of 1 minute.
func NewAny[T any](options ...AnyOption[T]) *Any[T] {
	c := Any[T]{
		ttl: defaultTTL,
	}
	for _, option := range options {
		option(&c)
	}
	return &c
}

// Set updates the value in the cache and sets the expiry to now+TTL.
func (c *Any[T]) Set(value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = value
	c.expiry = time.Now().Add(c.ttl)
}

// Get retrieves the value from the cache. If cache has expired, the second
// return value will be false.
func (c *Any[T]) Get() (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.expiry) {
		var zero T
		return zero, false
	}
	return c.data, true
}
