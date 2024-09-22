package sshserver

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/bus"
	"github.com/uselagoon/ssh-portal/internal/k8s"
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
func pubKeyAuth(
	log *slog.Logger,
	nc *nats.Conn,
	c *k8s.Client,
) ssh.PublicKeyHandler {
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
		queryData, err := json.Marshal(bus.SSHAccessQuery{
			SSHFingerprint: fingerprint,
			NamespaceName:  ctx.User(),
			ProjectID:      pid,
			EnvironmentID:  eid,
			SessionID:      ctx.SessionID(),
		})
		if err != nil {
			log.Warn("couldn't marshal NATS request", slog.Any("error", err))
			return false
		}
		// send query
		msg, err := nc.Request(bus.SubjectSSHAccessQuery, queryData, natsTimeout)
		if err != nil {
			log.Warn("couldn't make NATS request", slog.Any("error", err))
			return false
		}
		// handle response
		var ok bool
		if err := json.Unmarshal(msg.Data, &ok); err != nil {
			log.Warn("couldn't unmarshal response", slog.Any("response", msg.Data))
			return false
		}
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
