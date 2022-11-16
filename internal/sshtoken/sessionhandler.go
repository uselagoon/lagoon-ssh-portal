package sshtoken

import (
	"context"
	"fmt"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	UserAccessToken(context.Context, *uuid.UUID) (string, error)
}

var (
	sessionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "session_total",
		Help: "The total number of ssh sessions started",
	})
	tokensGeneratedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tokens_generated_total",
		Help: "The total number of Lagoon authentication tokens generated",
	})
)

// sessionHandler returns a ssh.Handler which writes a Lagoon access token to
// the session stream and then closes the connection.
func sessionHandler(log *zap.Logger, k KeycloakService) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		// extract required info from the session context
		sid, ok := s.Context().Value(ssh.ContextKeySessionID).(string)
		if !ok {
			log.Warn("couldn't get session ID from context",
				zap.String("sessionID", sid))
			_, err := fmt.Fprintf(s.Stderr(), "internal error. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		uid, ok := s.Context().Value(userUUID).(*uuid.UUID)
		if !ok {
			log.Warn("couldn't get user UUID from context",
				zap.String("sessionID", sid))
			_, err := fmt.Fprintf(s.Stderr(), "internal error. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// validate the command. right now we only support "token".
		cmd := s.Command()
		if len(cmd) != 1 || cmd[0] != "token" {
			log.Debug("invalid command",
				zap.Strings("command", cmd),
				zap.String("sessionID", sid))
			_, err := fmt.Fprintf(s.Stderr(),
				"invalid command: only \"token\" is supported. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// get the user access token from keycloak
		accessToken, err := k.UserAccessToken(s.Context(), uid)
		if err != nil {
			log.Warn("couldn't get user access token",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(),
				"internal error. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// send token response
		_, err = fmt.Fprintf(s, "%s\n", accessToken)
		if err != nil {
			log.Debug("couldn't write token to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
			return
		}
		tokensGeneratedTotal.Inc()
		log.Info("generated token for user",
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()))
	}
}
