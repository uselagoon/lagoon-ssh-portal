package sshtoken

import (
	"context"
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

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	UserBySSHFingerprint(context.Context, string) (*lagoondb.User, error)
}

var (
	authnAttemptsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_authentication_attempts_total",
		Help: "The total number of ssh-token authentication attempts",
	})
	authnSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_authentication_success_total",
		Help: "The total number of successful ssh-token authentications",
	})
	authnAttemptsNonLagoonUser = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_authentication_attempts_non_lagoon_user",
		Help: "The total number of failed authentication attempts with a user other than lagoon",
	})
)

// pubKeyAuth returns a ssh.PublicKeyHandler which accepts any key which
// matches a user, and the associated user UUID to the ssh context.
func pubKeyAuth(log *zap.Logger, l LagoonDBService) ssh.PublicKeyHandler {
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
		// validate user string
		if ctx.User() != "lagoon" {
			authnAttemptsNonLagoonUser.Inc()
			log.Debug(`invalid user: only "lagoon" is supported`,
				zap.String("sessionID", ctx.SessionID()),
				zap.String("user", ctx.User()))
			return false
		}
		// identify Lagoon user by ssh key fingerprint
		fingerprint := gossh.FingerprintSHA256(pubKey)
		user, err := l.UserBySSHFingerprint(ctx, fingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint",
					zap.String("sessionID", ctx.SessionID()))
			} else {
				log.Warn("couldn't query for user by SSH key fingerprint",
					zap.String("sessionID", ctx.SessionID()),
					zap.Error(err))
			}
			return false
		}
		// The SSH key fingerprint was in the database so authentication was
		// successful. Inject the user UUID into the context so it can be used in
		// the session handler.
		authnSuccessTotal.Inc()
		ctx.SetValue(userUUID, user.UUID)
		log.Info("authentication successful",
			zap.String("sessionID", ctx.SessionID()),
			zap.String("fingerprint", fingerprint))
		return true
	}
}
