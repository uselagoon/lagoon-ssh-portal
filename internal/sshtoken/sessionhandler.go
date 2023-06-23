package sshtoken

import (
	"context"
	"fmt"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	llib "github.com/uselagoon/machinery/api/lagoon"
	lclient "github.com/uselagoon/machinery/api/lagoon/client"
	"github.com/uselagoon/machinery/utils/jwt"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"go.uber.org/zap"
)

// KeycloakTokenService provides methods for querying the Keycloak API for user
// access tokens.
type KeycloakTokenService interface {
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
	redirectsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshtoken_redirects_total",
		Help: "The total number of ssh redirect responses served",
	})
)

// tokenSession returns a bare access token or full access token response based
// on the user ID
func tokenSession(s ssh.Session, log *zap.Logger,
	keycloakToken KeycloakTokenService, uid *uuid.UUID) {
	// valid commands:
	// - grant: returns a full access token response as per
	//   https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
	// - token: returns a bare access token (the contents of the access_token
	//   field inside a full token access token response)
	sid := s.Context().SessionID()
	cmd := s.Command()
	if len(cmd) != 1 {
		log.Debug("too many arguments",
			zap.Strings("command", cmd),
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()))
		_, err := fmt.Fprintf(s.Stderr(),
			"invalid command: only \"grant\" and \"token\" are supported. SID: %s\r\n",
			sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	// get response
	var response string
	var err error
	switch cmd[0] {
	case "grant":
		response, err = keycloakToken.UserAccessTokenResponse(s.Context(), uid)
		if err != nil {
			log.Warn("couldn't get user access token response",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(),
				"internal error. SID: %s\r\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.String("userUUID", uid.String()),
					zap.Error(err))
			}
			return
		}
	case "token":
		response, err = keycloakToken.UserAccessToken(s.Context(), uid)
		if err != nil {
			log.Warn("couldn't get user access token",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
			_, err = fmt.Fprintf(s.Stderr(),
				"internal error. SID: %s\r\n", sid)
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", sid),
					zap.String("userUUID", uid.String()),
					zap.Error(err))
			}
			return
		}
	default:
		log.Debug("invalid command",
			zap.Strings("command", cmd),
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()))
		_, err := fmt.Fprintf(s.Stderr(),
			"invalid command: only \"grant\" and \"token\" are supported. SID: %s\r\n",
			sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	// send response
	_, err = fmt.Fprintf(s, "%s\r\n", response)
	if err != nil {
		log.Debug("couldn't write response to session stream",
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

// redirectSession inspects the user string, and if it matches a namespace that
// the user has access to, returns an error message to the user with the SSH
// endpoint to use for ssh shell access. If the user doesn't have access to the
// environment a generic error message is returned.
func redirectSession(s ssh.Session, log *zap.Logger,
	keycloakUserInfo KeycloakTokenService, lconf lagoon.LagoonClientConfig,
	uid *uuid.UUID) {
	sid := s.Context().SessionID()
	// get the users token
	userToken, err := keycloakUserInfo.UserAccessToken(s.Context(), uid)
	if err != nil {
		log.Error("couldn't query user roles and groups",
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()),
			zap.Error(err))
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n", sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	// set up a lagoon client for use in the following process
	token, err := jwt.GenerateAdminToken(lconf.JWTToken, lconf.JWTAudience, "ssh-portal-api", "ssh-portal-api", time.Now().Unix(), 60)
	if err != nil {
		// the token wasn't generated
		log.Error("couldn't generate jwt token",
			zap.Error(err))
		return
	}
	lc := lclient.New(lconf.APIGraphqlEndpoint, "ssh-portal-api", &token, false)
	env, err := llib.GetEnvironmentByNamespace(s.Context(), s.User(), lc)
	if err != nil {
		log.Error("couldn't query environment",
			zap.Any("query", s.User()), zap.Error(err))
		return
	}
	if err != nil {
		log.Error("couldn't get environment by namespace name",
			zap.String("namespaceName", s.User()),
			zap.String("userUUID", uid.String()),
			zap.String("sessionID", sid),
			zap.Error(err))
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n", sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	// check permission
	lc = lclient.New(lconf.APIGraphqlEndpoint, "ssh-portal-api-user-request", &userToken, false)
	_, err = llib.UserCanSSHToEnvironment(s.Context(), s.User(), lc)
	ok := false
	if err == nil {
		ok = true
	}
	if !ok {
		log.Info("user cannot SSH to environment",
			zap.Uint("environmentID", env.ID),
			zap.Uint("projectID", env.ProjectID),
			zap.String("environmentName", env.Name),
			zap.String("namespace", s.User()),
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()))
		log.Debug("user permissions",
			zap.String("userUUID", uid.String()))
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n", sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	log.Info("user can SSH to environment",
		zap.Uint("environmentID", env.ID),
		zap.Uint("projectID", env.ProjectID),
		zap.String("environmentName", env.Name),
		zap.String("namespace", s.User()),
		zap.String("sessionID", sid),
		zap.String("userUUID", uid.String()))
	log.Debug("user permissions",
		zap.String("userUUID", uid.String()))

	sshEndpoint, err := llib.SSHEndpointByNamespace(s.Context(), s.User(), lc)
	if err != nil {
		log.Error("couldn't get ssh endpoint by environment ID",
			zap.String("namespaceName", s.User()),
			zap.String("userUUID", uid.String()),
			zap.String("sessionID", sid),
			zap.Uint("environmentID", env.ID),
			zap.Error(err))
		_, err = fmt.Fprintf(s.Stderr(),
			"This SSH server does not provide shell access. SID: %s\r\n", sid)
		if err != nil {
			log.Debug("couldn't write error message to session stream",
				zap.String("sessionID", sid),
				zap.String("userUUID", uid.String()),
				zap.Error(err))
		}
		return
	}
	preamble :=
		"This SSH server does not provide shell access to your environment.\r\n" +
			"To SSH into your environment use this endpoint:\r\n\n"
	// send response
	if sshEndpoint.DeployTarget.SSHHost == "22" {
		_, err = fmt.Fprintf(s.Stderr(),
			preamble+"\tssh %s@%s\r\n\nSID: %s\r\n",
			s.User(), sshEndpoint.DeployTarget.SSHHost, sid)
	} else {
		_, err = fmt.Fprintf(s.Stderr(),
			preamble+"\tssh -p %s %s@%s\r\n\nSID: %s\r\n",
			sshEndpoint.DeployTarget.SSHPort, s.User(), sshEndpoint.DeployTarget.SSHHost, sid)
	}
	if err != nil {
		log.Debug("couldn't write response to session stream",
			zap.String("sessionID", sid),
			zap.String("userUUID", uid.String()),
			zap.Error(err))
		return
	}
	redirectsTotal.Inc()
	log.Info("redirected user to SSH portal endpoint",
		zap.String("sessionID", sid),
		zap.String("namespaceName", s.User()),
		zap.String("userUUID", uid.String()),
		zap.String("sshHost", sshEndpoint.DeployTarget.SSHHost),
		zap.String("sshPort", sshEndpoint.DeployTarget.SSHPort))
}

// sessionHandler returns a ssh.Handler which writes a Lagoon access token to
// the session stream and then closes the connection.
func sessionHandler(log *zap.Logger,
	keycloakToken KeycloakTokenService,
	lconf lagoon.LagoonClientConfig) ssh.Handler {
	return func(s ssh.Session) {
		sessionTotal.Inc()
		// extract required info from the session context
		uid, ok := s.Context().Value(userUUID).(*uuid.UUID)
		if !ok {
			log.Warn("couldn't get user UUID from context",
				zap.String("sessionID", s.Context().SessionID()))
			_, err := fmt.Fprintf(s.Stderr(), "internal error. SID: %s\r\n",
				s.Context().SessionID())
			if err != nil {
				log.Debug("couldn't write error message to session stream",
					zap.String("sessionID", s.Context().SessionID()),
					zap.Error(err))
			}
			return
		}
		if s.User() == "lagoon" {
			tokenSession(s, log, keycloakToken, uid)
		} else {
			redirectSession(s, log, keycloakToken, lconf, uid)
		}
	}
}
