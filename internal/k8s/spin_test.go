package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestSpinAfter(t *testing.T) {
	wait := 500 * time.Millisecond
	var testCases = map[string]struct {
		connectTime   time.Duration
		expectSpinner bool
	}{
		"spinner":    {connectTime: 600 * time.Millisecond, expectSpinner: true},
		"no spinner": {connectTime: 400 * time.Millisecond, expectSpinner: false},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			var buf strings.Builder
			// start the spinner with a given connect time
			ctx, cancel := context.WithTimeout(tt.Context(), tc.connectTime)
			wg := spinAfter(ctx, &buf, wait)
			wg.Wait()
			cancel()
			// check if the builder has spinner animations
			if tc.expectSpinner {
				assert.NotZero(tt, buf.Len(), name)
			} else {
				assert.Zero(tt, buf.Len(), name)
			}
		})
	}
}
