package sshserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"k8s.io/utils/exec"
)

// K8SAPIService provides methods for querying the Kubernetes API.
type K8SAPIService interface {
	Exec(context.Context, string, string, string, []string, io.ReadWriter,
		io.Writer, bool, <-chan ssh.Window) error
	FindDeployment(context.Context, string, string) (string, error)
	Logs(context.Context, string, string, string, bool, int64, io.ReadWriter) error
}

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
func sessionHandler(log *slog.Logger, c K8SAPIService,
	sftp, logAccessEnabled bool) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		ctx := s.Context()
		log := log.With(slog.String("sessionID", ctx.SessionID()))
		log.Debug("starting session",
			slog.Any("rawCommand", s.Command()),
			slog.String("subsystem", s.Subsystem()),
		)
		// parse the command line arguments to extract any service or container args
		service, container, logs, rawCmd := parseConnectionParams(s.Command())
		// validate the service and container
		if err := k8s.ValidateLabelValue(service); err != nil {
			log.Debug("invalid service name",
				slog.String("service", service),
				slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid service name %s. SID: %s\r\n",
				service, ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write to session stream", slog.Any("error", err))
			}
			return
		}
		if err := k8s.ValidateLabelValue(container); err != nil {
			log.Debug("invalid container name",
				slog.String("container", container),
				slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(), "invalid container name %s. SID: %s\r\n",
				container, ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write to session stream", slog.Any("error", err))
			}
			return
		}
		// find the deployment name based on the given service name
		deployment, err := c.FindDeployment(ctx, s.User(), service)
		if err != nil {
			log.Debug("couldn't find deployment for service",
				slog.String("service", service),
				slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(), "unknown service %s. SID: %s\r\n",
				service, ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write to session stream", slog.Any("error", err))
			}
			return
		}
		// extract info passed through the context by the authhandler
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
		if len(logs) != 0 {
			if !logAccessEnabled {
				log.Debug("logs access is not enabled",
					slog.String("logsArgument", logs))
				_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
					ctx.SessionID())
				if err != nil {
					log.Warn("couldn't send error to client", slog.Any("error", err))
				}
				// Send a non-zero exit code to the client on internal logs error.
				// OpenSSH uses 255 for this, 254 is an exec failure, so use 253 to
				// differentiate this error.
				if err = s.Exit(253); err != nil {
					log.Warn("couldn't send exit code to client", slog.Any("error", err))
				}
				return
			}
			follow, tailLines, err := parseLogsArg(service, logs, rawCmd)
			if err != nil {
				log.Debug("couldn't parse logs argument",
					slog.String("logsArgument", logs),
					slog.Any("error", err))
				_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
					ctx.SessionID())
				if err != nil {
					log.Warn("couldn't send error to client", slog.Any("error", err))
				}
				// Send a non-zero exit code to the client on internal logs error.
				// OpenSSH uses 255 for this, 254 is an exec failure, so use 253 to
				// differentiate this error.
				if err = s.Exit(253); err != nil {
					log.Warn("couldn't send exit code to client", slog.Any("error", err))
				}
				return
			}
			log.Info("sending logs to SSH client",
				slog.Int("environmentID", eid),
				slog.Int("projectID", pid),
				slog.String("SSHFingerprint", fingerprint),
				slog.String("container", container),
				slog.String("deployment", deployment),
				slog.String("environmentName", ename),
				slog.String("namespace", s.User()),
				slog.String("projectName", pname),
				slog.Bool("follow", follow),
				slog.Int64("tailLines", tailLines),
			)
			doLogs(ctx, log, s, deployment, container, follow, tailLines, c)
			return
		}
		// handle sftp and sh fallback
		cmd := getSSHIntent(sftp, rawCmd)
		// check if a pty was requested, and get the window size channel
		_, winch, pty := s.Pty()
		log.Info("executing SSH command",
			slog.Bool("pty", pty),
			slog.Int("environmentID", eid),
			slog.Int("projectID", pid),
			slog.String("SSHFingerprint", fingerprint),
			slog.String("container", container),
			slog.String("deployment", deployment),
			slog.String("environmentName", ename),
			slog.String("namespace", s.User()),
			slog.String("projectName", pname),
			slog.Any("command", cmd),
		)
		doExec(ctx, log, s, deployment, container, cmd, c, pty, winch)
	}
}

// startClientKeepalive sends a keepalive request to the client via the channel
// embedded in ssh.Session at a regular interval. If the client fails to
// respond, the channel is closed, and cancel is called.
func startClientKeepalive(ctx context.Context, cancel context.CancelFunc,
	log *slog.Logger, s ssh.Session) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// https://github.com/openssh/openssh-portable/blob/
			// 	edc2ef4e418e514c99701451fae4428ec04ce538/serverloop.c#L127-L158
			_, err := s.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Debug("client closed connection", slog.Any("error", err))
				_ = s.Close()
				cancel()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func doLogs(ctx ssh.Context, log *slog.Logger, s ssh.Session, deployment,
	container string, follow bool, tailLines int64, c K8SAPIService) {
	// Wrap the ssh.Context so we can cancel goroutines started from this
	// function without affecting the SSH session.
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// In a multiplexed connection (multiple SSH channels to the single TCP
	// connection), if the client disconnects from the channel the session
	// context will not be cancelled (because the TCP connection is still up),
	// and k8s.Logs() will hang.
	//
	// To work around this problem, start a goroutine to send a regular keepalive
	// ping to the client. If the keepalive fails, close the channel and cancel
	// the childCtx.
	go startClientKeepalive(childCtx, cancel, log, s)
	err := c.Logs(childCtx, s.User(), deployment, container, follow, tailLines, s)
	if err != nil {
		log.Warn("couldn't send logs", slog.Any("error", err))
		_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Warn("couldn't send error to client", slog.Any("error", err))
		}
		// Send a non-zero exit code to the client on internal logs error.
		// OpenSSH uses 255 for this, 254 is an exec failure, so use 253 to
		// differentiate this error.
		if err = s.Exit(253); err != nil {
			log.Warn("couldn't send exit code to client", slog.Any("error", err))
		}
	}
	log.Debug("finished command logs")
}

func doExec(ctx ssh.Context, log *slog.Logger, s ssh.Session, deployment,
	container string, cmd []string, c K8SAPIService, pty bool,
	winch <-chan ssh.Window) {
	err := c.Exec(ctx, s.User(), deployment, container, cmd, s,
		s.Stderr(), pty, winch)
	if err != nil {
		if exitErr, ok := err.(exec.ExitError); ok {
			log.Debug("couldn't execute command", slog.Any("error", err))
			if err = s.Exit(exitErr.ExitStatus()); err != nil {
				log.Warn("couldn't send exit code to client", slog.Any("error", err))
			}
		} else {
			log.Warn("couldn't execute command", slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(), "error executing command. SID: %s\r\n",
				ctx.SessionID())
			if err != nil {
				log.Warn("couldn't send error to client", slog.Any("error", err))
			}
			// Send a non-zero exit code to the client on internal exec error.
			// OpenSSH uses 255 for this, so use 254 to differentiate the error.
			if err = s.Exit(254); err != nil {
				log.Warn("couldn't send exit code to client", slog.Any("error", err))
			}
		}
	}
	log.Debug("finished command exec")
}
