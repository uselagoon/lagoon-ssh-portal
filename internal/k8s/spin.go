package k8s

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	framerate = 50 * time.Millisecond
)

var (
	charset = []string{`|`, `/`, `-`, `\`}
)

// spinAfter will wait for the given time period and if the given context is
// not cancelled will start animating a spinner on w until the given context
// is cancelled.
//
// If the given context is cancelled before the wait duration, nothing is
// written to w.
//
// The returned *sync.WaitGroup should be waited on to ensure the spinner
// finishes cleaning up the animation.
func spinAfter(ctx context.Context, w io.Writer, wait time.Duration) *sync.WaitGroup {
	var wg sync.WaitGroup
	wt := time.NewTimer(wait)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-wt.C:
			spin(ctx, w)
		}
	}()
	return &wg
}

// spin animates a spinner on w until ctx is cancelled.
func spin(ctx context.Context, w io.Writer) {
	for {
		select {
		case <-ctx.Done():
			// https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_(Control_Sequence_Introducer)_sequences
			_, _ = fmt.Fprint(w, "\033[2K")
			return
		default:
			for _, char := range charset {
				_, _ = fmt.Fprintf(w, "%s getting you a shell\r", char)
				time.Sleep(framerate)
			}
		}
	}
}
