// Package metrics implements the prometheus metrics server.
package metrics

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewServer returns a *http.Server serving prometheus metrics in a new
// goroutine.
// Caller should defer Shutdown() for cleanup.
func NewServer(log *slog.Logger, addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	s := http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  16 * time.Second,
		WriteTimeout: 16 * time.Second,
	}
	go func() {
		if err := s.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("metrics server did not shut down cleanly", slog.Any("error", err))
		}
	}()
	return &s
}
