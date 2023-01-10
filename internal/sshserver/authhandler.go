package sshserver

import (
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	"go.uber.org/zap"
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
func pubKeyAuth(log *zap.Logger, nc *nats.EncodedConn,
	c *k8s.Client) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		authAttemptsTotal.Inc()
		// parse SSH public key
		pubKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Warn("couldn't parse SSH public key",
				zap.String("sessionID", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// get Lagoon labels from namespace if available
		eid, pid, ename, pname, err := c.NamespaceDetails(ctx, ctx.User())
		if err != nil {
			log.Debug("couldn't get namespace details",
				zap.String("sessionID", ctx.SessionID()),
				zap.String("namespace", ctx.User()), zap.Error(err))
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
		var response bool
		err = nc.Request(sshportalapi.SubjectSSHAccessQuery, q, &response,
			natsTimeout)
		if err != nil {
			log.Warn("couldn't make NATS request",
				zap.String("sessionID", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// handle response
		if response {
			authSuccessTotal.Inc()
			ctx.SetValue(environmentIDKey, eid)
			ctx.SetValue(environmentNameKey, ename)
			ctx.SetValue(projectIDKey, pid)
			ctx.SetValue(projectNameKey, pname)
			ctx.SetValue(sshFingerprint, fingerprint)
			log.Debug("Lagoon authorization granted",
				zap.String("sessionID", ctx.SessionID()),
				zap.String("fingerprint", fingerprint),
				zap.String("namespace", ctx.User()))
			return true
		}
		return false
	}
}
