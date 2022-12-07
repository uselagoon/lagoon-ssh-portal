package sshtoken

import (
	"errors"

	"github.com/gliderlabs/ssh"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

type ctxKey int

const (
	userUUID ctxKey = iota
)

var (
	authnAttemptsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_authentication_attempts_total",
		Help: "The total number of ssh-token authentication attempts",
	})
	authnSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_authentication_success_total",
		Help: "The total number of successful ssh-token authentications",
	})
)

// pubKeyAuth returns a ssh.PublicKeyHandler which accepts any key which
// matches a user, and the associated user UUID to the ssh context.
func pubKeyAuth(log *zap.Logger, ldb LagoonDBService) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		authnAttemptsTotal.Inc()
		// parse SSH public key
		pubKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Warn("couldn't parse SSH public key",
				zap.String("sessionID", ctx.SessionID()),
				zap.Error(err))
			return false
		}
		// identify Lagoon user by ssh key fingerprint
		fingerprint := gossh.FingerprintSHA256(pubKey)
		user, err := ldb.UserBySSHFingerprint(ctx, fingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint",
					zap.String("sessionID", ctx.SessionID()))
			} else {
				log.Warn("couldn't query for user by SSH key fingerprint",
					zap.String("sessionID", ctx.SessionID()),
					zap.String("fingerprint", fingerprint),
					zap.Error(err))
			}
			return false
		}
		// The SSH key fingerprint was in the database so "authentication" was
		// successful. Inject the user UUID into the context so it can be used in
		// the session handler.
		authnSuccessTotal.Inc()
		ctx.SetValue(userUUID, user.UUID)
		log.Info("authentication successful",
			zap.String("sessionID", ctx.SessionID()),
			zap.String("fingerprint", fingerprint),
			zap.String("userID", user.UUID.String()))
		return true
	}
}
