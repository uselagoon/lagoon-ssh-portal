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
		Help: "The total number of ssh sessions started",
	})
)

// sessionHandler returns a ssh.Handler which connects the ssh session to the
// requested container.
//
// If sftp is true, the returned ssh.Handler can be type converted to a sftp
// ssh.SubsystemHandler. The only practical difference in the returned session
// handler is that the command is set to sftp-server. This implies that the
// target container must have a sftp-server binary installed for sftp to work.
// There is no support for a built-in sftp server.
func sessionHandler(log *zap.Logger, c *k8s.Client, sftp bool) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		sid, ok := s.Context().Value(ssh.ContextKeySessionID).(string)
		if !ok {
			log.Warn("couldn't get session ID")
			return
		}
		// start the command
		log.Debug("starting command exec",
			zap.String("session-id", sid),
			zap.Strings("raw command", s.Command()),
			zap.String("subsystem", s.Subsystem()),
		)
		// parse the command line arguments to extract any service or container args
		service, container, cmd := parseConnectionParams(s.Command())
		if sftp {
			cmd = []string{"sftp-server"}
		}
		// validate the service and container
		if err := k8s.ValidateLabelValue(service); err != nil {
			log.Debug("invalid service name",
				zap.String("service", service),
				zap.String("session-id", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid service name %s. SID: %s\r\n",
				service, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("session-id", sid),
					zap.Error(err))
			}
			return
		}
		if err := k8s.ValidateLabelValue(container); err != nil {
			log.Debug("invalid container name",
				zap.String("container", container),
				zap.String("session-id", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid container name %s. SID: %s\r\n",
				container, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("session-id", sid),
					zap.Error(err))
			}
			return
		}
		// find the deployment name based on the given service name
		deployment, err := c.FindDeployment(s.Context(), s.User(), service)
		if err != nil {
			log.Debug("couldn't find deployment for service",
				zap.String("service", service),
				zap.String("session-id", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "unknown service %s. SID: %s\r\n",
				service, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("session-id", sid),
					zap.Error(err))
			}
			return
		}
		// check if a pty was requested
		_, _, pty := s.Pty()
		log.Info("executing command",
			zap.String("namespace", s.User()),
			zap.String("deployment", deployment),
			zap.String("container", container),
			zap.Strings("command", cmd),
			zap.Bool("pty", pty),
			zap.String("session-id", sid),
		)
		err = c.Exec(s.Context(), s.User(), deployment, container, cmd, s,
			s.Stderr(), pty)
		if err != nil {
			log.Warn("couldn't execute command",
				zap.String("session-id", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
				sid)
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
