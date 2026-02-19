package sshserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	gossh "golang.org/x/crypto/ssh"
	"k8s.io/utils/exec"
)

// K8SAPIService provides methods for querying the Kubernetes API.
type K8SAPIService interface {
	Exec(context.Context, string, string, string, []string, io.ReadWriter,
		io.Writer, bool, <-chan ssh.Window) error
	FindDeployment(context.Context, string, string) (string, error)
	LagoonContainerLogs(
		ctx context.Context,
		namespace,
		deployment,
		container string,
		follow bool,
		tailLines int64,
		stdio io.ReadWriter,
	) error
	LagoonSystemLogs(
		ctx context.Context,
		namespace,
		lagoonSystem,
		jobName string,
		follow bool,
		tailLines int64,
		stdio io.ReadWriter,
	) error
	NamespaceDetails(context.Context, string) (int, int, string, string, error)
}

var (
	sessionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportal_sessions_total",
		Help: "The total number of ssh-portal sessions started",
	})
	execSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sshportal_exec_sessions",
		Help: "Current number of ssh-portal exec sessions",
	})
	lagoonContainerLogsSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sshportal_lagoon_container_logs_sessions",
		Help: "Current number of ssh-portal lagoon container logs sessions",
	})
	lagoonSystemLogsSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sshportal_lagoon_system_logs_sessions",
		Help: "Current number of ssh-portal lagoon system logs sessions",
	})
)

// logAccessNotEnabled notifies the client that log access is not enabled and
// returns an error to the client.
func logAccessNotEnabled(s ssh.Session, log *slog.Logger) {
	log.Debug("log access is not enabled")
	_, err := fmt.Fprintf(s.Stderr(), "log access is not enabled. SID: %s\r\n",
		s.Context().SessionID())
	if err != nil {
		log.Debug("couldn't send error to client", slog.Any("error", err))
	}
	// Send a non-zero exit code to the client on internal logs error.
	// OpenSSH uses 255 for this, 254 is an exec failure, so use 253 to
	// differentiate this error.
	if err = s.Exit(253); err != nil {
		log.Warn("couldn't send exit code to client", slog.Any("error", err))
	}
}

// permissionsUnmarshal extracts details of the Lagoon environment identified
// in the pubKeyHandler which were stored in the Extensions field of the ssh
// connection. See permissionsMarshal.
func permissionsUnmarshal(ctx ssh.Context) (int, int, string, string, error) {
	var eid, pid int
	var ename, pname string
	var err error
	eidString, ok := ctx.Permissions().Extensions[environmentIDKey]
	if !ok {
		return eid, pid, ename, pname,
			fmt.Errorf("missing environmentID in permissions")
	}
	eid, err = strconv.Atoi(eidString)
	if err != nil {
		return eid, pid, ename, pname,
			fmt.Errorf("couldn't parse environmentID in permissions")
	}
	pidString, ok := ctx.Permissions().Extensions[projectIDKey]
	if !ok {
		return eid, pid, ename, pname,
			fmt.Errorf("missing projectID in permissions")
	}
	pid, err = strconv.Atoi(pidString)
	if err != nil {
		return eid, pid, ename, pname,
			fmt.Errorf("couldn't parse projectID in permissions")
	}
	ename, ok = ctx.Permissions().Extensions[environmentNameKey]
	if !ok {
		return eid, pid, ename, pname,
			fmt.Errorf("missing environmentName in permissions")
	}
	pname, ok = ctx.Permissions().Extensions[projectNameKey]
	if !ok {
		return eid, pid, ename, pname,
			fmt.Errorf("missing projectName in permissions")
	}
	return eid, pid, ename, pname, nil
}

// getSSHIntent analyses the SFTP flag and the raw command strings to determine
// if the command should be wrapped, and returns the given cmd wrapped
// appropriately.
func getSSHIntent(sftp bool, rawCmd string) []string {
	// if this is an sftp session we ignore any commands
	if sftp {
		return []string{"sftp-server", "-u", "0002"}
	}
	// if there is no command, assume the user wants a shell
	if len(rawCmd) == 0 {
		return []string{"sh"}
	}
	// if there is a command, wrap it in a shell the way openssh does
	// https://github.com/openssh/openssh-portable/blob/
	// 	73dcca12115aa12ed0d123b914d473c384e52651/session.c#L1705-L1713
	return []string{"sh", "-c", rawCmd}
}

// sessionHandler returns a ssh.Handler which connects the ssh session to the
// requested container.
//
// If sftp is true, the returned ssh.Handler can be type converted to a sftp
// ssh.SubsystemHandler. The only practical difference in the returned session
// handler is that the command is set to sftp-server. This implies that the
// target container must have a sftp-server binary installed for sftp to work.
// There is no support for a built-in sftp server.
func sessionHandler(
	log *slog.Logger,
	c K8SAPIService,
	sftp,
	logAccessEnabled bool,
) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		ctx := s.Context()
		log := log.With(slog.String("sessionID", ctx.SessionID()))
		log.Debug("starting session",
			// s.Command() returns a slice of strings split on space and parsed as
			// posix shell arguments:
			// https://github.com/gliderlabs/ssh/blob/
			//  a8ecd3ed244fb77c863c0cf30ccdcca44436974a/session.go#L201-L204
			slog.Any("command", s.Command()),
			// s.RawCommand() returns a string containing the arguments supplied to
			// the ssh client joined by a single space:
			// https://github.com/openssh/openssh-portable/blob/
			//	fe4305c37ffe53540a67586854e25f05cf615849/ssh.c#L1179-L1184
			slog.String("rawCommand", s.RawCommand()),
			slog.String("subsystem", s.Subsystem()),
		)
		// parse command line arguments to determine the session type
		switch parseSessionType(s.Command()) {
		case ExecSession:
			execSession(log, c, s, sftp)
		case LagoonContainerLogsSession:
			if !logAccessEnabled {
				logAccessNotEnabled(s, log)
				return
			}
			lagoonContainerLogsSession(log, c, s)
		case LagoonSystemLogsSession:
			if !logAccessEnabled {
				logAccessNotEnabled(s, log)
				return
			}
			lagoonSystemLogsSession(log, c, s)
		default:
			log.Error("couldn't determine session type",
				slog.Any("command", s.Command()))
			_, err := fmt.Fprintf(s.Stderr(), "invalid session type. SID: %s\r\n",
				s.Context().SessionID())
			if err != nil {
				log.Debug("couldn't send error to client", slog.Any("error", err))
			}
			return
		}
	}
}

// execSession handles a command execution session.
func execSession(
	log *slog.Logger,
	c K8SAPIService,
	s ssh.Session,
	sftp bool,
) {
	ctx := s.Context()
	service, container, rawCmd, err :=
		parseExecSessionParams(s.Command(), s.RawCommand())
	if err != nil {
		log.Debug("couldn't parse exec session parameters",
			slog.Any("command", s.Command()),
			slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "invalid exec session parameters. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
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
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	// extract info passed through the context by the authhandler
	eid, pid, ename, pname, err := permissionsUnmarshal(ctx)
	if err != nil {
		log.Error("couldn't unmarshal permissions", slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "error executing command. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	// handle sftp and sh fallback
	cmd := getSSHIntent(sftp, rawCmd)
	// check if a pty was requested, and get the window size channel
	_, winch, pty := s.Pty()
	log.Info("executing SSH command",
		slog.Int("environmentID", eid),
		slog.Int("projectID", pid),
		slog.String("SSHFingerprint", gossh.FingerprintSHA256(s.PublicKey())),
		slog.String("container", container),
		slog.String("deployment", deployment),
		slog.String("environmentName", ename),
		slog.String("namespace", s.User()),
		slog.String("projectName", pname),
		slog.Bool("pty", pty),
		slog.Any("command", cmd),
	)
	// update metrics
	execSessions.Inc()
	defer execSessions.Dec()
	// execute command
	err = c.Exec(
		ctx, s.User(), deployment, container, cmd, s, s.Stderr(), pty, winch)
	if err != nil {
		if exitErr, ok := err.(exec.ExitError); ok {
			log.Debug("command execution error",
				slog.Int("exitStatus", exitErr.ExitStatus()),
				slog.Any("error", err))
			if err = s.Exit(exitErr.ExitStatus()); err != nil {
				log.Warn("couldn't send exit code to client", slog.Any("error", err))
			}
		} else {
			log.Warn("couldn't execute command", slog.Any("error", err))
			_, err = fmt.Fprintf(
				s.Stderr(), "error executing command. SID: %s\r\n", ctx.SessionID())
			if err != nil {
				log.Debug("couldn't send error to client", slog.Any("error", err))
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

// handleLogsErr inspects the given error, logs the details, and returns an
// appropriate message to the ssh session.
func handleLogsErr(s ssh.Session, log *slog.Logger, err error) {
	var errMsg string
	if errors.Is(err, k8s.ErrNoSelectorMatch) {
		errMsg = err.Error()
	} else {
		errMsg = "log stream interrupted"
	}
	log.Info(errMsg, slog.Any("error", err))
	_, err = fmt.Fprintf(
		s.Stderr(), "%s. SID: %s\r\n", errMsg, s.Context().SessionID())
	if err != nil {
		log.Debug("couldn't send error to client", slog.Any("error", err))
	}
	// Send a non-zero exit code to the client on internal logs error.
	// OpenSSH uses 255 for this, 254 is an exec failure, so use 253 to
	// differentiate this error.
	if err = s.Exit(253); err != nil {
		log.Debug("couldn't send exit code to client", slog.Any("error", err))
	}
}

// lagoonContainerLogsSession handles a log access session.
func lagoonContainerLogsSession(
	log *slog.Logger,
	c K8SAPIService,
	s ssh.Session,
) {
	ctx := s.Context()
	service, container, logs, err := parseContainerLogsSessionParams(s.Command())
	if err != nil {
		log.Debug("couldn't parse container logs session parameters",
			slog.Any("command", s.Command()),
			slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(),
			"invalid container logs session parameters. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	follow, tailLines, err := parseLogsArg(logs)
	if err != nil {
		log.Debug("couldn't parse container logs argument",
			slog.String("logsArgument", logs),
			slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "invalid container logs argument. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
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
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	// extract info passed through the context by the authhandler
	eid, pid, ename, pname, err := permissionsUnmarshal(ctx)
	if err != nil {
		log.Error("couldn't unmarshal permissions", slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "error executing command. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	log.Info("sending container logs to SSH client",
		slog.Int("environmentID", eid),
		slog.Int("projectID", pid),
		slog.String("SSHFingerprint", gossh.FingerprintSHA256(s.PublicKey())),
		slog.String("container", container),
		slog.String("deployment", deployment),
		slog.String("environmentName", ename),
		slog.String("namespace", s.User()),
		slog.String("projectName", pname),
		slog.Bool("follow", follow),
		slog.Int64("tailLines", tailLines),
	)
	// update metrics
	lagoonContainerLogsSessions.Inc()
	defer lagoonContainerLogsSessions.Dec()
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
	err = c.LagoonContainerLogs(
		childCtx, s.User(), deployment, container, follow, tailLines, s)
	if err != nil {
		handleLogsErr(s, log, err)
	}
	log.Debug("finished command container logs")
}

func lagoonSystemLogsSession(
	log *slog.Logger,
	c K8SAPIService,
	s ssh.Session,
) {
	ctx := s.Context()
	lagoonSystem, name, logs, err :=
		parseSystemLogsSessionParams(s.Command())
	if err != nil {
		log.Debug("couldn't parse system logs session parameters",
			slog.Any("command", s.Command()),
			slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(),
			"invalid system logs session parameters. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	follow, tailLines, err := parseLogsArg(logs)
	if err != nil {
		log.Debug("couldn't parse system logs argument",
			slog.String("logsArgument", logs),
			slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "invalid system logs argument. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	// extract info passed through the context by the authhandler
	eid, pid, ename, pname, err := permissionsUnmarshal(ctx)
	if err != nil {
		log.Error("couldn't unmarshal permissions", slog.Any("error", err))
		_, err = fmt.Fprintf(
			s.Stderr(), "error executing command. SID: %s\r\n", ctx.SessionID())
		if err != nil {
			log.Debug("couldn't send error to client", slog.Any("error", err))
		}
		return
	}
	log.Info("sending system logs to SSH client",
		slog.Int("environmentID", eid),
		slog.Int("projectID", pid),
		slog.String("SSHFingerprint", gossh.FingerprintSHA256(s.PublicKey())),
		slog.String("lagoonSystem", lagoonSystem.String()),
		slog.String("name", name),
		slog.String("environmentName", ename),
		slog.String("namespace", s.User()),
		slog.String("projectName", pname),
		slog.Bool("follow", follow),
		slog.Int64("tailLines", tailLines),
	)
	// update metrics
	lagoonSystemLogsSessions.Inc()
	defer lagoonSystemLogsSessions.Dec()
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
	err = c.LagoonSystemLogs(
		childCtx, s.User(), lagoonSystem.String(), name, follow, tailLines, s)
	if err != nil {
		handleLogsErr(s, log, err)
	}
	log.Debug("finished command system logs")
}
