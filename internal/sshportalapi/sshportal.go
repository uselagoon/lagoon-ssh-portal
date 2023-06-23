package sshportalapi

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	llib "github.com/uselagoon/machinery/api/lagoon"
	lclient "github.com/uselagoon/machinery/api/lagoon/client"
	"github.com/uselagoon/machinery/utils/jwt"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

const (
	// SubjectSSHAccessQuery defines the NATS subject for SSH access queries.
	SubjectSSHAccessQuery = "lagoon.sshportal.api"
)

// SSHAccessQuery defines the structure of an SSH access query.
type SSHAccessQuery struct {
	SSHFingerprint string
	NamespaceName  string
	ProjectID      int
	EnvironmentID  int
	SessionID      string
}

var (
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportalapi_requests_total",
		Help: "The total number of ssh-portal-api requests received",
	})
)

func sshportal(ctx context.Context, log *zap.Logger, c *nats.EncodedConn,
	k KeycloakTokenService, lconf lagoon.LagoonClientConfig) nats.Handler {
	return func(_, replySubject string, query *SSHAccessQuery) {
		var realmRoles, userGroups []string
		var groupProjectIDs map[string][]int
		// set up tracing and update metrics
		ctx, span := otel.Tracer(pkgName).Start(ctx, SubjectSSHAccessQuery)
		defer span.End()
		requestsCounter.Inc()
		// sanity check the query
		if query.SSHFingerprint == "" || query.NamespaceName == "" {
			log.Warn("malformed sshportal query", zap.Any("query", query))
			return
		}

		// set up a lagoon client for use in the following process
		token, err := jwt.GenerateAdminToken(lconf.JWTToken, lconf.JWTAudience, "ssh-portal-api", "ssh-portal-api", time.Now().Unix(), 60)
		if err != nil {
			// the token wasn't generated
			log.Error("couldn't generate jwt token",
				zap.Any("query", query),
				zap.Error(err))
			return
		}
		lc := lclient.New(lconf.APIGraphqlEndpoint, "ssh-portal-api", &token, false)
		// get the environment
		env, err := llib.GetEnvironmentByNamespace(ctx, query.NamespaceName, lc)
		if err != nil {
			log.Error("couldn't query environment",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// sanity check the environment we found
		// if this check fails it likely means a collision in
		// project+environment -> namespace_name mapping, or some similar logic
		// error.
		if (query.ProjectID != 0 && uint(query.ProjectID) != env.ProjectID) ||
			(query.EnvironmentID != 0 && uint(query.EnvironmentID) != env.ID) {
			log.Warn("ID mismatch in environment identification",
				zap.Any("query", query), zap.Any("env", env), zap.Error(err))
			if err = c.Publish(replySubject, false); err != nil {
				log.Error("couldn't publish reply",
					zap.Any("query", query),
					zap.Bool("reply", false),
					zap.Error(err))
			}
			return
		}
		// get the user
		user, err := llib.UserBySSHFingerprint(ctx, query.SSHFingerprint, lc)
		if err != nil {
			log.Error("couldn't query user by ssh fingerprint",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// get the user token
		userToken, err := k.UserAccessToken(ctx, user.ID)
		if err != nil {
			log.Error("couldn't query user roles and groups",
				zap.Any("query", query),
				zap.String("userUUID", user.ID.String()),
				zap.Error(err))
			return
		}
		log.Debug("keycloak user attributes",
			zap.Strings("realmRoles", realmRoles),
			zap.Strings("userGroups", userGroups),
			zap.Any("groupProjectIDs", groupProjectIDs),
			zap.String("userUUID", user.ID.String()),
			zap.String("sessionID", query.SessionID),
		)
		// check permission using the token generated for the specific user
		lc = lclient.New(lconf.APIGraphqlEndpoint, "ssh-portal-api-user-request", &userToken, false)
		_, err = llib.UserCanSSHToEnvironment(ctx, query.NamespaceName, lc)
		var logMsg string
		ok := false
		if err != nil {
			logMsg = "SSH access not authorized"
		} else {
			logMsg = "SSH access authorized"
			ok = true
		}
		log.Info(logMsg,
			zap.Uint("environmentID", env.ID),
			zap.Uint("projectID", env.ProjectID),
			zap.String("SSHFingerprint", query.SSHFingerprint),
			zap.String("environmentName", env.Name),
			zap.String("namespace", query.NamespaceName),
			// zap.String("projectName", env.ProjectName),
			zap.String("sessionID", query.SessionID),
			zap.String("userUUID", user.ID.String()),
		)
		if err = c.Publish(replySubject, ok); err != nil {
			log.Error("couldn't publish reply",
				zap.Any("query", query),
				zap.Bool("reply", ok),
				zap.String("userUUID", user.ID.String()),
				zap.Error(err))
		}
	}
}
