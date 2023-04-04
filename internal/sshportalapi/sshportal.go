package sshportalapi

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
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
	p *rbac.Permission, l LagoonDBService, k KeycloakService) nats.Handler {
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
		// get the environment
		env, err := l.EnvironmentByNamespaceName(ctx, query.NamespaceName)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Warn("unknown namespace name",
					zap.Any("query", query), zap.Error(err))
				if err = c.Publish(replySubject, false); err != nil {
					log.Error("couldn't publish reply",
						zap.Any("query", query),
						zap.Bool("reply", false),
						zap.Error(err))
				}
				return
			}
			log.Error("couldn't query environment",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// sanity check the environment we found
		// if this check fails it likely means a collision in
		// project+environment -> namespace_name mapping, or some similar logic
		// error.
		if (query.ProjectID != 0 && query.ProjectID != env.ProjectID) ||
			(query.EnvironmentID != 0 && query.EnvironmentID != env.ID) {
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
		user, err := l.UserBySSHFingerprint(ctx, query.SSHFingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint",
					zap.Any("query", query), zap.Error(err))
				if err = c.Publish(replySubject, false); err != nil {
					log.Error("couldn't publish reply",
						zap.Any("query", query),
						zap.Bool("reply", false),
						zap.String("userUUID", user.UUID.String()),
						zap.Error(err))
				}
				return
			}
			log.Error("couldn't query user by ssh fingerprint",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// get the user roles and groups
		realmRoles, userGroups, groupProjectIDs, err =
			k.UserRolesAndGroups(ctx, user.UUID)
		if err != nil {
			log.Error("couldn't query user roles and groups",
				zap.Any("query", query),
				zap.String("userUUID", user.UUID.String()),
				zap.Error(err))
			return
		}
		// check permission
		ok := p.UserCanSSHToEnvironment(ctx, env, realmRoles, userGroups,
			groupProjectIDs)
		var logMsg string
		if ok {
			logMsg = "SSH access authorized"
		} else {
			logMsg = "SSH access not authorized"
		}
		log.Info(logMsg,
			zap.Int("environmentID", env.ID),
			zap.Int("projectID", env.ProjectID),
			zap.String("SSHFingerprint", query.SSHFingerprint),
			zap.String("environmentName", env.Name),
			zap.String("namespace", query.NamespaceName),
			zap.String("projectName", env.ProjectName),
			zap.String("sessionID", query.SessionID),
			zap.String("userUUID", user.UUID.String()),
		)
		if err = c.Publish(replySubject, ok); err != nil {
			log.Error("couldn't publish reply",
				zap.Any("query", query),
				zap.Bool("reply", ok),
				zap.String("userUUID", user.UUID.String()),
				zap.Error(err))
		}
	}
}
