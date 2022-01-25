package signalctx

import (
	"context"
	"os"
	"os/signal"
)

// GetContext starts a goroutine to handle ^C gracefully, and returns a context
// with a "cancel" function which cleans up the signal handling and ensures the
// goroutine exits. This "cancel" function should be deferred in Run().
func GetContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		select {
		case <-signalChan:
			cancel()
		case <-ctx.Done():
		}
		<-signalChan
		os.Exit(130) // https://tldp.org/LDP/abs/html/exitcodes.html
	}()
	return ctx, func() { signal.Stop(signalChan); cancel() }
}
