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
			c := cache.NewAny[int](cache.AnyWithTTL[int](time.Second))
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
		key     string
		value   string
		expired bool
	}{
		"expired": {
			key:     "foo",
			value:   "bar",
			expired: true,
		},
		"not expired": {
			key:   "foo",
			value: "bar",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			c := cache.NewMap[string, string](
				cache.MapWithTTL[string, string](time.Second),
			)
			c.Set(tc.key, tc.value)
			if tc.expired {
				time.Sleep(2 * time.Second)
				value, ok := c.Get(tc.key)
				assert.False(tt, ok, name)
				assert.Equal(tt, "", value, name)
			} else {
				value, ok := c.Get(tc.key)
				assert.True(tt, ok, name)
				assert.Equal(tt, tc.value, value, name)
			}
		})
	}
}
