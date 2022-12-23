package k8s

import (
	"context"

	"github.com/gliderlabs/ssh"
	"k8s.io/client-go/tools/remotecommand"
)

type termSizeQueue struct {
	send chan *remotecommand.TerminalSize
}

// newTermSizeQueue returns a termSizeQueue which implements the
// remotecommand.TerminalSizeQueue interface. It starts a goroutine which exits
// when the given context is done.
func newTermSizeQueue(ctx context.Context, winch <-chan ssh.Window) *termSizeQueue {
	tsq := termSizeQueue{
		send: make(chan *remotecommand.TerminalSize, 1),
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(tsq.send)
				return
			case window := <-winch:
				tsq.send <- &remotecommand.TerminalSize{
					Width:  uint16(window.Width),
					Height: uint16(window.Height),
				}
			}
		}
	}()
	return &tsq
}

func (t *termSizeQueue) Next() *remotecommand.TerminalSize {
	return <-t.send
}
