package k8s

import (
	"context"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/gliderlabs/ssh"
	"k8s.io/client-go/tools/remotecommand"
)

func TestTermSizeQueue(t *testing.T) {
	var testCases = map[string]struct {
		input  ssh.Window
		expect remotecommand.TerminalSize
	}{
		"term size change": {
			input: ssh.Window{
				Width:  100,
				Height: 200,
			},
			expect: remotecommand.TerminalSize{
				Width:  100,
				Height: 200,
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			in := make(chan ssh.Window, 1)
			tsq := newTermSizeQueue(ctx, in)
			in <- tc.input
			output := tsq.Next()
			assert.Equal(tt, tc.expect, *output, name)
		})
	}
}
