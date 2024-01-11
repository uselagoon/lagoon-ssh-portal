package sshserver

import (
	"log/slog"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	gossh "golang.org/x/crypto/ssh"
)

type ctxKey int

const (
	environmentIDKey ctxKey = iota
	environmentNameKey
	projectIDKey
	projectNameKey
	sshFingerprint
)

var (
	natsTimeout = 8 * time.Second
)

var (
	authAttemptsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportal_authentication_attempts_total",
		Help: "The total number of ssh-portal authentication attempts",
	})
	authSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportal_authentication_success_total",
		Help: "The total number of successful ssh-portal authentications",
	})
)

// pubKeyAuth returns a ssh.PublicKeyHandler which queries the remote
// ssh-portal-api for Lagoon SSH authorization.
func pubKeyAuth(log *slog.Logger, nc *nats.EncodedConn,
	c *k8s.Client) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		authAttemptsTotal.Inc()
		log := log.With(slog.String("sessionID", ctx.SessionID()))
		// parse SSH public key
		pubKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Warn("couldn't parse SSH public key", slog.Any("error", err))
			return false
		}
		// get Lagoon labels from namespace if available
		eid, pid, ename, pname, err := c.NamespaceDetails(ctx, ctx.User())
		if err != nil {
			log.Debug("couldn't get namespace details",
				slog.String("namespace", ctx.User()), slog.Any("error", err))
			return false
		}
		// construct ssh access query
		fingerprint := gossh.FingerprintSHA256(pubKey)
		q := sshportalapi.SSHAccessQuery{
			SSHFingerprint: fingerprint,
			NamespaceName:  ctx.User(),
			ProjectID:      pid,
			EnvironmentID:  eid,
			SessionID:      ctx.SessionID(),
		}
		// send query
		var ok bool
		err = nc.Request(sshportalapi.SubjectSSHAccessQuery, q, &ok, natsTimeout)
		if err != nil {
			log.Warn("couldn't make NATS request", slog.Any("error", err))
			return false
		}
		// handle response
		if !ok {
			log.Debug("SSH access not authorized",
				slog.String("fingerprint", fingerprint),
				slog.String("namespace", ctx.User()))
			return false
		}
		authSuccessTotal.Inc()
		ctx.SetValue(environmentIDKey, eid)
		ctx.SetValue(environmentNameKey, ename)
		ctx.SetValue(projectIDKey, pid)
		ctx.SetValue(projectNameKey, pname)
		ctx.SetValue(sshFingerprint, fingerprint)
		log.Debug("SSH access authorized",
			slog.String("fingerprint", fingerprint),
			slog.String("namespace", ctx.User()))
		return true
	}
}
