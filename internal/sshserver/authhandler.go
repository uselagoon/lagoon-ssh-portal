package sshserver

import (
	"bytes"
	"encoding/json"
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

var (
	natsTimeout = 8 * time.Second
)

var (
	authAttemptsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "authentication_attempts_total",
		Help: "The total number of authentication attempts",
	})
	authSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "authentication_success_total",
		Help: "The total number of successful authentication",
	})
)

// pubKeyAuth returns a ssh.PublicKeyHandler which accepts any key, and simply
// adds the given key to the connection context.
func pubKeyAuth(log *zap.Logger, nc *nats.Conn,
	c *k8s.Client) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		authAttemptsTotal.Inc()
		// parse SSH public key
		pubKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Warn("couldn't parse SSH public key",
				zap.String("session-id", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// get Lagoon labels from namespace if available
		pid, eid, err := c.NamespaceDetails(ctx, ctx.User())
		if err != nil {
			log.Debug("couldn't get namespace details",
				zap.String("session-id", ctx.SessionID()),
				zap.String("namespace", ctx.User()), zap.Error(err))
			return false
		}
		// construct and marshal ssh access query
		fingerprint := gossh.FingerprintSHA256(pubKey)
		data, err := json.Marshal(&sshportalapi.SSHAccessQuery{
			SSHFingerprint: fingerprint,
			NamespaceName:  ctx.User(),
			ProjectID:      pid,
			EnvironmentID:  eid,
			SessionID:      ctx.SessionID(),
		})
		if err != nil {
			log.Warn("couldn't marshal SSHAccessQuery",
				zap.String("session-id", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// send query
		response, err := nc.Request(sshportalapi.SubjectSSHAccessQuery, data,
			natsTimeout)
		if err != nil {
			log.Warn("couldn't make NATS request",
				zap.String("session-id", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// handle response
		if bytes.Equal(response.Data, []byte("true")) {
			authSuccessTotal.Inc()
			log.Debug("authentication successful",
				zap.String("session-id", ctx.SessionID()),
				zap.String("fingerprint", fingerprint),
				zap.String("namespace", ctx.User()))
			return true
		}
		return false
	}
}
