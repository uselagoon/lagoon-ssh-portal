package sshserver

import (
	"fmt"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"go.uber.org/zap"
	"k8s.io/utils/exec"
)

var (
	sessionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportal_sessions_total",
		Help: "The total number of ssh-portal sessions started",
	})
)

// getSSHIntent analyses the SFTP flag and the raw command strings to determine
// if the command should be wrapped.
func getSSHIntent(sftp bool, cmd []string) []string {
	// if this is an sftp session we ignore any commands
	if sftp {
		return []string{"sftp-server", "-u", "0002"}
	}
	// if there is no command, assume the user wants a shell
	if len(cmd) == 0 {
		return []string{"sh"}
	}
	// if there is a command, wrap it in a shell the way openssh does
	// https://github.com/openssh/openssh-portable/blob/
	// 	73dcca12115aa12ed0d123b914d473c384e52651/session.c#L1705-L1713
	return []string{"sh", "-c", strings.Join(cmd, " ")}
}

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
		sid := s.Context().SessionID()
		// start the command
		log.Debug("starting command exec",
			zap.String("sessionID", sid),
			zap.Strings("rawCommand", s.Command()),
			zap.String("subsystem", s.Subsystem()),
		)
		// parse the command line arguments to extract any service or container args
		service, container, rawCmd := parseConnectionParams(s.Command())
		cmd := getSSHIntent(sftp, rawCmd)
		// validate the service and container
		if err := k8s.ValidateLabelValue(service); err != nil {
			log.Debug("invalid service name",
				zap.String("service", service),
				zap.String("sessionID", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid service name %s. SID: %s\r\n",
				service, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		if err := k8s.ValidateLabelValue(container); err != nil {
			log.Debug("invalid container name",
				zap.String("container", container),
				zap.String("sessionID", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid container name %s. SID: %s\r\n",
				container, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// find the deployment name based on the given service name
		deployment, err := c.FindDeployment(s.Context(), s.User(), service)
		if err != nil {
			log.Debug("couldn't find deployment for service",
				zap.String("service", service),
				zap.String("sessionID", sid),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(), "unknown service %s. SID: %s\r\n",
				service, sid)
			if err != nil {
				log.Debug("couldn't write to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// check if a pty was requested, and get the window size channel
		_, winch, pty := s.Pty()
		// extract info passed through the context by the authhandler
		ctx := s.Context()
		eid, ok := ctx.Value(environmentIDKey).(int)
		if !ok {
			log.Warn("couldn't extract environment ID from session context")
		}
		ename, ok := ctx.Value(environmentNameKey).(string)
		if !ok {
			log.Warn("couldn't extract environment name from session context")
		}
		pid, ok := ctx.Value(projectIDKey).(int)
		if !ok {
			log.Warn("couldn't extract project ID from session context")
		}
		pname, ok := ctx.Value(projectNameKey).(string)
		if !ok {
			log.Warn("couldn't extract project name from session context")
		}
		fingerprint, ok := ctx.Value(sshFingerprint).(string)
		if !ok {
			log.Warn("couldn't extract SSH key fingerprint from session context")
		}
		log.Info("executing SSH command",
			zap.Bool("pty", pty),
			zap.Int("environmentID", eid),
			zap.Int("projectID", pid),
			zap.String("SSHFingerprint", fingerprint),
			zap.String("container", container),
			zap.String("deployment", deployment),
			zap.String("environmentName", ename),
			zap.String("namespace", s.User()),
			zap.String("projectName", pname),
			zap.String("sessionID", sid),
			zap.Strings("command", cmd),
		)
		err = c.Exec(s.Context(), s.User(), deployment, container, cmd, s,
			s.Stderr(), pty, winch)
		if err != nil {
			if exitErr, ok := err.(exec.ExitError); ok {
				log.Debug("couldn't execute command",
					zap.String("sessionID", sid),
					zap.Error(err))
				if err = s.Exit(exitErr.ExitStatus()); err != nil {
					log.Warn("couldn't send exit code to client",
						zap.String("sessionID", sid),
						zap.Error(err))
				}
			} else {
				log.Warn("couldn't execute command",
					zap.String("sessionID", sid),
					zap.Error(err))
				_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
					sid)
				if err != nil {
					log.Warn("couldn't send error to client",
						zap.String("sessionID", sid),
						zap.Error(err))
				}
				// Send a non-zero exit code to the client on internal exec error.
				// OpenSSH uses 255 for this, so use 254 to differentiate the error.
				if err = s.Exit(254); err != nil {
					log.Warn("couldn't send exit code to client",
						zap.String("sessionID", sid),
						zap.Error(err))
				}
			}
		}
		log.Debug("finished command exec",
			zap.String("sessionID", sid))
	}
}
