package k8s

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestLinewiseCopy(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect []string
		prefix string
	}{
		"logs": {
			input:  "foo\nbar\nbaz\n",
			expect: []string{"test: foo", "test: bar", "test: baz"},
			prefix: "test:",
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			out := make(chan string, 1)
			in := io.NopCloser(strings.NewReader(tc.input))
			go linewiseCopy(ctx, tc.prefix, out, in)
			timer := time.NewTimer(500 * time.Millisecond)
			var lines []string
		loop:
			for {
				select {
				case <-timer.C:
					break loop
				case line := <-out:
					lines = append(lines, line)
				}
			}
			assert.Equal(tt, tc.expect, lines, name)
		})
	}
}
