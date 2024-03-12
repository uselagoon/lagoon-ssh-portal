package k8s

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestIntFromLabel(t *testing.T) {
	labels := map[string]string{
		"foo":      "1",
		"bar":      "hello",
		"baz":      "true",
		"negative": "-1",
		"max":      "9223372036854775807",
		"overflow": "9223372036854775808",
	}
	var testCases = map[string]struct {
		target    string
		expect    int
		expectErr bool
	}{
		"foo":      {target: "foo", expect: 1},
		"bar":      {target: "bar", expectErr: true},
		"baz":      {target: "baz", expectErr: true},
		"negative": {target: "negative", expect: -1},
		"max":      {target: "max", expect: 9223372036854775807},
		"overflow": {target: "overflow", expectErr: true},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			result, err := intFromLabel(labels, tc.target)
			if tc.expectErr {
				assert.Error(tt, err, name)
			} else {
				assert.NoError(tt, err, name)
				assert.Equal(tt, tc.expect, result, name)
			}
		})
	}
}
