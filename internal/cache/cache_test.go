package cache_test

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/uselagoon/ssh-portal/internal/cache"
)

func TestIntCache(t *testing.T) {
	var testCases = map[string]struct {
		input   int
		expect  int
		expired bool
	}{
		"not expired": {input: 11, expect: 11},
		"expired":     {input: 11, expired: true},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			c := cache.NewCache[int](cache.WithTTL[int](time.Second))
			c.Set(tc.input)
			if tc.expired {
				time.Sleep(2 * time.Second)
				_, ok := c.Get()
				assert.False(tt, ok, name)
			} else {
				value, ok := c.Get()
				assert.True(tt, ok, name)
				assert.Equal(tt, tc.expect, value, name)
			}
		})
	}
}

func TestMapCache(t *testing.T) {
	var testCases = map[string]struct {
		input   map[string]string
		expect  map[string]string
		expired bool
	}{
		"expired": {
			input:   map[string]string{"foo": "bar"},
			expired: true,
		},
		"not expired": {
			input:  map[string]string{"foo": "bar"},
			expect: map[string]string{"foo": "bar"},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			c := cache.NewCache[map[string]string](
				cache.WithTTL[map[string]string](time.Second),
			)
			c.Set(tc.input)
			if tc.expired {
				time.Sleep(2 * time.Second)
				_, ok := c.Get()
				assert.False(tt, ok, name)
			} else {
				value, ok := c.Get()
				assert.True(tt, ok, name)
				assert.Equal(tt, tc.expect, value, name)
			}
		})
	}
}
