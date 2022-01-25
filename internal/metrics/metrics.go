package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// NewServer returns a *http.Server serving prometheus metrics in a new
// goroutine.
// Caller should defer Shutdown() for cleanup.
func NewServer(log *zap.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	s := http.Server{
		Addr:         ":9911",
		Handler:      mux,
		ReadTimeout:  16 * time.Second,
		WriteTimeout: 16 * time.Second,
	}
	go func() {
		if err := s.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("metrics server did not shut down cleanly", zap.Error(err))
		}
	}()
	return &s
}
