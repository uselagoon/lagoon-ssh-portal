package sshtoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
)

// KeycloakTokenService provides methods for querying the Keycloak API for user
// access tokens.
type KeycloakTokenService interface {
	UserAccessTokenResponse(context.Context, *uuid.UUID) (string, error)
	UserAccessToken(context.Context, *uuid.UUID) (string, error)
}

// KeycloakUserInfoService provides methods for querying the Keycloak API for
// permission information contained in service-api user tokens.
type KeycloakUserInfoService interface {
	lagoon.KeycloakService
	UserRolesAndGroups(context.Context, *uuid.UUID) ([]string, []string, error)
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
func tokenSession(s ssh.Session, log *slog.Logger,
	keycloakToken KeycloakTokenService, uid *uuid.UUID) {
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
		response, err = keycloakToken.UserAccessTokenResponse(ctx, uid)
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
		response, err = keycloakToken.UserAccessToken(ctx, uid)
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
	keycloakUserInfo KeycloakUserInfoService,
	ldb LagoonDBService,
	uid *uuid.UUID,
) {
	ctx := s.Context()
	// get the user roles and groups
	realmRoles, userGroups, err :=
		keycloakUserInfo.UserRolesAndGroups(s.Context(), uid)
	if err != nil {
		log.Error("couldn't query user roles and groups",
			slog.Any("error", err))
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n",
			ctx.SessionID())
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				slog.Any("error", err))
		}
		return
	}
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
		slog.String("namespaceName", s.User()),
		slog.String("projectName", env.ProjectName),
	)
	groupNameProjectIDsMap, err :=
		lagoon.GroupNameProjectIDsMap(ctx, ldb, keycloakUserInfo, userGroups)
	if err != nil {
		log.Error("couldn't generate group name to project IDs map",
			slog.Any("error", err))
		return
	}
	// check permission
	ok := p.UserCanSSHToEnvironment(s.Context(), env, realmRoles,
		userGroups, groupNameProjectIDsMap)
	if !ok {
		log.Info("user cannot SSH to environment")
		log.Debug("user permissions",
			slog.Any("realmRoles", realmRoles),
			slog.Any("userGroups", userGroups),
			slog.Any("groupProjectIDs", groupNameProjectIDsMap))
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
	log.Debug("user permissions",
		slog.Any("realmRoles", realmRoles),
		slog.Any("userGroups", userGroups),
		slog.Any("groupProjectIDs", groupNameProjectIDsMap))
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

// sessionHandler returns a ssh.Handler which writes a Lagoon access token to
// the session stream and then closes the connection.
func sessionHandler(log *slog.Logger, p *rbac.Permission,
	keycloakToken KeycloakTokenService,
	keycloakPermission KeycloakUserInfoService,
	ldb LagoonDBService) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		// extract required info from the session context
		ctx := s.Context()
		log := log.With(slog.String("sessionID", ctx.SessionID()))
		uid, ok := ctx.Value(userUUID).(*uuid.UUID)
		if !ok {
			log.Warn("couldn't get user UUID from context")
			_, err := fmt.Fprintf(s.Stderr(), "internal error. SID: %s\r\n",
				ctx.SessionID())
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					slog.Any("error", err))
			}
			return
		}
		log = log.With(slog.String("userUUID", uid.String()))
		if s.User() == "lagoon" {
			tokenSession(s, log, keycloakToken, uid)
		} else {
			redirectSession(s, log, p, keycloakPermission, ldb, uid)
		}
	}
}
