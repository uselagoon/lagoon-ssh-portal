package k8s_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/uselagoon/ssh-portal/internal/k8s"
)

func TestValidateLabelValues(t *testing.T) {
	var testCases = map[string]struct {
		input       string
		expectError bool
	}{
		"valid":   {input: "foo", expectError: false},
		"invalid": {input: "naïve", expectError: true},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			if tc.expectError {
				assert.Error(tt, k8s.ValidateLabelValue(tc.input), name)
			} else {
				assert.NoError(tt, k8s.ValidateLabelValue(tc.input), name)
			}
		})
	}
}
