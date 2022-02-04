package sshserver

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"go.uber.org/zap"
)

var (
	sessionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "session_total",
		Help: "The total number of ssh sessions",
	})
)

func sessionHandler(log *zap.Logger, c *k8s.Client) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		sid, ok := s.Context().Value(ssh.ContextKeySessionID).(string)
		if !ok {
			log.Warn("couldn't get session ID")
			return
		}
		// check if a pty is required
		_, _, pty := s.Pty()
		// start the command
		log.Debug("starting command exec",
			zap.String("session-id", sid))
		// TODO: handle the custom command parameters such as service=...
		err := c.Exec(s.Context(), "cli", s.User(), s.Command(), s, s.Stderr(), pty)
		if err != nil {
			log.Warn("couldn't execute command",
				zap.String("session-id", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s, "couldn't execute command. SID: %s\n", sid)
			if err != nil {
				log.Warn("couldn't send error to client",
					zap.String("session-id", sid),
					zap.Error(err))
			}
		}
		log.Debug("finished command exec",
			zap.String("session-id", sid))
	}
}
