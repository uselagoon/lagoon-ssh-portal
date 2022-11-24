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
	UserAccessTokenResponse(context.Context, *uuid.UUID) (string, error)
	UserAccessToken(context.Context, *uuid.UUID) (string, error)
}

var (
	sessionTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_sessions_total",
		Help: "The total number of ssh-token sessions started",
	})
	tokensGeneratedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_tokens_generated_total",
		Help: "The total number of ssh-token user access tokens generated",
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
		// valid commands:
		// - grant: returns a full access token response as per
		//   https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
		// - token: returns a bare access token (the contents of the access_token
		//   field inside a full token access token response)
		cmd := s.Command()
		if len(cmd) != 1 {
			log.Debug("too many arguments",
				zap.Strings("command", cmd),
				zap.String("sessionID", sid))
			_, err := fmt.Fprintf(s.Stderr(),
				"invalid command: only a single argument is supported. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// get response
		var response string
		var err error
		switch cmd[0] {
		case "grant":
			response, err = k.UserAccessTokenResponse(s.Context(), uid)
			if err != nil {
				log.Warn("couldn't get user access token response",
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
		case "token":
			response, err = k.UserAccessToken(s.Context(), uid)
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
		default:
			log.Debug("invalid command",
				zap.Strings("command", cmd),
				zap.String("sessionID", sid))
			_, err := fmt.Fprintf(s.Stderr(),
				"invalid command: only \"grant\" and \"token\" are supported. SID: %s\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.Error(err))
			}
			return
		}
		// send response
		_, err = fmt.Fprintf(s, "%s\n", response)
		if err != nil {
			log.Debug("couldn't write response to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
			return
		}
		tokensGeneratedTotal.Inc()
		log.Info("generated access token for user",
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()))
	}
}
