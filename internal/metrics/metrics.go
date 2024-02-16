// Package metrics implements the prometheus metrics server.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

const (
	metricsReadTimeout     = 2 * time.Second
	metricsShutdownTimeout = 2 * time.Second
)

// Serve runs a prometheus metrics server in goroutines managed by eg. It will
// gracefully exit with a two second timeout.
// Callers should Wait() on eg before exiting.
func Serve(ctx context.Context, eg *errgroup.Group, metricsPort string) {
	// configure metrics server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	metricsSrv := http.Server{
		Addr:         metricsPort,
		ReadTimeout:  metricsReadTimeout,
		WriteTimeout: metricsReadTimeout,
		Handler:      mux,
	}
	// start metrics server
	eg.Go(func() error {
		if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("metrics server exited with error: %v", err)
		}
		return nil
	})
	// start metrics server shutdown handler for graceful shutdown
	eg.Go(func() error {
		<-ctx.Done()
		timeoutCtx, cancel :=
			context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer cancel()
		return metricsSrv.Shutdown(timeoutCtx)
	})
}
