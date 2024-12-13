package sshtoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	gossh "golang.org/x/crypto/ssh"
)

// KeycloakTokenService provides methods for querying the Keycloak API for user
// access tokens.
type KeycloakTokenService interface {
	UserAccessTokenResponse(context.Context, uuid.UUID) (string, error)
	UserAccessToken(context.Context, uuid.UUID) (string, error)
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
	redirectsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_redirects_total",
		Help: "The total number of ssh redirect responses served",
	})
)

// tokenSession returns a bare access token or full access token response based
// on the user ID
func tokenSession(
	s ssh.Session,
	log *slog.Logger,
	keycloakToken KeycloakTokenService,
	userUUID uuid.UUID,
) {
	// valid commands:
	// - grant: returns a full access token response as per
	//   https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
	// - token: returns a bare access token (the contents of the access_token
	//   field inside a full token access token response)
	ctx := s.Context()
	cmd := s.Command()
	if len(cmd) != 1 {
		log.Debug("too many arguments",
			slog.Any("command", cmd))
		_, err := fmt.Fprintf(s.Stderr(),
			"invalid command: only \"grant\" and \"token\" are supported. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
	// get response
	var response string
	var err error
	switch cmd[0] {
	case "grant":
		response, err = keycloakToken.UserAccessTokenResponse(ctx, userUUID)
		if err != nil {
			log.Warn("couldn't get user access token response",
				slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(),
				"internal error. SID: %s\r\n", ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					slog.Any("error", err))
			}
			return
		}
	case "token":
		response, err = keycloakToken.UserAccessToken(ctx, userUUID)
		if err != nil {
			log.Warn("couldn't get user access token",
				slog.Any("error", err))
			_, err = fmt.Fprintf(s.Stderr(),
				"internal error. SID: %s\r\n",
				ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					slog.Any("error", err))
			}
			return
		}
	default:
		log.Debug("invalid command",
			slog.Any("command", cmd))
		_, err := fmt.Fprintf(s.Stderr(),
			"invalid command: only \"grant\" and \"token\" are supported. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
	// send response
	_, err = fmt.Fprintf(s, "%s\r\n", response)
	if err != nil {
		log.Debug("couldn't write response to session stream",
			slog.Any("error", err))
		return
	}
	tokensGeneratedTotal.Inc()
	log.Info("generated token for user")
}

// redirectSession inspects the user string, and if it matches a namespace that
// the user has access to, returns an error message to the user with the SSH
// endpoint to use for ssh shell access. If the user doesn't have access to the
// environment a generic error message is returned.
func redirectSession(
	s ssh.Session,
	log *slog.Logger,
	p *rbac.Permission,
	ldb LagoonDBService,
	userUUID uuid.UUID,
) {
	ctx := s.Context()
	env, err := ldb.EnvironmentByNamespaceName(s.Context(), s.User())
	if err != nil {
		if errors.Is(err, lagoondb.ErrNoResult) {
			log.Info("unknown namespace name",
				slog.String("namespaceName", s.User()),
				slog.Any("error", err))
		} else {
			log.Error("couldn't get environment by namespace name",
				slog.String("namespaceName", s.User()),
				slog.Any("error", err))
		}
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
	log = log.With(
		slog.Int("environmentID", env.ID),
		slog.Int("projectID", env.ProjectID),
		slog.String("environmentName", env.Name),
		slog.String("environmentType", env.Type.String()),
		slog.String("namespaceName", s.User()),
		slog.String("projectName", env.ProjectName),
		slog.String("userUUID", userUUID.String()),
	)
	// check permission
	ok, err := p.UserCanSSHToEnvironment(
		s.Context(), log, userUUID, env.ProjectID, env.Type)
	if err != nil {
		log.Error("couldn't check if user can ssh to environment")
	}
	if !ok {
		log.Info("user cannot SSH to environment")
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
	log.Info("user can SSH to environment")
	sshHost, sshPort, err := ldb.SSHEndpointByEnvironmentID(s.Context(), env.ID)
	if err != nil {
		if errors.Is(err, lagoondb.ErrNoResult) {
			log.Warn("no results for ssh endpoint by environment ID",
				slog.Any("error", err))
		} else {
			log.Error("couldn't get ssh endpoint by environment ID",
				slog.Any("error", err))
		}
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
	preamble :=
		"This SSH server does not provide shell access to your environment.\r\n" +
			"To SSH into your environment use this endpoint:\r\n\n"
	// send response
	if sshPort == "22" {
		_, err = fmt.Fprintf(s.Stderr(),
			preamble+"\tssh %s@%s\r\n\nSID: %s\r\n",
			s.User(), sshHost, ctx.SessionID())
	} else {
		_, err = fmt.Fprintf(s.Stderr(),
			preamble+"\tssh -p %s %s@%s\r\n\nSID: %s\r\n",
			sshPort, s.User(), sshHost, ctx.SessionID())
	}
	if err != nil {
		log.Debug("couldn't write response to session stream",
			slog.Any("error", err))
		return
	}
	redirectsTotal.Inc()
	log.Info("redirected user to SSH portal endpoint",
		slog.String("sshHost", sshHost),
		slog.String("sshPort", sshPort))
}

// permissionsUnmarshal extracts the user UUID identified in the pubKeyHandler
// which was stored in the Extensions field of the ssh connection. See
// permissionsMarshal.
func permissionsUnmarshal(ctx ssh.Context) (uuid.UUID, error) {
	userUUIDString, ok := ctx.Permissions().Extensions[userUUIDKey]
	if !ok {
		return uuid.UUID{}, fmt.Errorf("missing userUUID in permissions")
	}
	return uuid.Parse(userUUIDString)
}

// sessionHandler returns a ssh.Handler which writes a Lagoon access token to
// the session stream and then closes the connection.
func sessionHandler(
	log *slog.Logger,
	p *rbac.Permission,
	keycloakToken KeycloakTokenService,
	ldb LagoonDBService,
) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		ctx := s.Context()
		fingerprint := gossh.FingerprintSHA256(s.PublicKey())
		log = log.With(
			slog.String("fingerprint", fingerprint),
			slog.String("sessionID", ctx.SessionID()),
		)
		// update last_used, since at this point the key has been used to
		// authenticate the session
		if err := ldb.SSHKeyUsed(ctx, fingerprint, time.Now()); err != nil {
			log.Error("couldn't update ssh key last used: %v",
				slog.Any("error", err))
			return
		}
		// Get the user UUID to pass on to the tokenSession or redirectSession
		userUUID, err := permissionsUnmarshal(ctx)
		if err != nil {
			log.Warn(
				"couldn't get userUUID from ssh session context",
				slog.Any("error", err))
			_, err := fmt.Fprintf(s.Stderr(), "internal error. SID: %s\r\n",
				ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					slog.Any("error", err))
			}
			return
		}
		log = log.With(slog.String("userUUID", userUUID.String()))
		if s.User() == "lagoon" {
			tokenSession(s, log, keycloakToken, userUUID)
		} else {
			redirectSession(s, log, p, ldb, userUUID)
		}
	}
}
