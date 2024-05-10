package sshportalapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"go.opentelemetry.io/otel"
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

// LogValue implements the slog.LogValuer interface.
func (q SSHAccessQuery) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("sshFingerprint", q.SSHFingerprint),
		slog.String("namespaceName", q.NamespaceName),
		slog.Int("projectID", q.ProjectID),
		slog.Int("environmentID", q.EnvironmentID),
		slog.String("sessionID", q.SessionID),
	)
}

var (
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportalapi_requests_total",
		Help: "The total number of ssh-portal-api requests received",
	})
)

func sshportal(
	ctx context.Context,
	log *slog.Logger,
	c *nats.EncodedConn,
	p *rbac.Permission,
	l LagoonDBService,
	k KeycloakService,
) nats.Handler {
	return func(_, replySubject string, query *SSHAccessQuery) {
		var realmRoles, userGroups []string
		// set up tracing and update metrics
		ctx, span := otel.Tracer(pkgName).Start(ctx, SubjectSSHAccessQuery)
		defer span.End()
		requestsCounter.Inc()
		log := log.With(slog.Any("query", query))
		// sanity check the query
		if query.SSHFingerprint == "" || query.NamespaceName == "" {
			log.Warn("malformed sshportal query")
			return
		}
		// get the environment
		env, err := l.EnvironmentByNamespaceName(ctx, query.NamespaceName)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Warn("unknown namespace name", slog.Any("error", err))
				if err = c.Publish(replySubject, false); err != nil {
					log.Error("couldn't publish reply", slog.Any("error", err))
				}
				return
			}
			log.Error("couldn't query environment", slog.Any("error", err))
			return
		}
		// sanity check the environment we found
		// if this check fails it likely means a collision in
		// project+environment -> namespace_name mapping, or some similar logic
		// error.
		if (query.ProjectID != 0 && query.ProjectID != env.ProjectID) ||
			(query.EnvironmentID != 0 && query.EnvironmentID != env.ID) {
			log.Warn("ID mismatch in environment identification",
				slog.Any("env", env),
				slog.Any("error", err))
			if err = c.Publish(replySubject, false); err != nil {
				log.Error("couldn't publish reply", slog.Any("error", err))
			}
			return
		}
		// get the user
		user, err := l.UserBySSHFingerprint(ctx, query.SSHFingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint", slog.Any("error", err))
				if err = c.Publish(replySubject, false); err != nil {
					log.Error("couldn't publish reply", slog.Any("error", err))
				}
				return
			}
			log.Error("couldn't query user by ssh fingerprint", slog.Any("error", err))
			return
		}
		// get the user roles and groups
		realmRoles, userGroups, err = k.UserRolesAndGroups(ctx, user.UUID)
		if err != nil {
			log.Error("couldn't query keycloak user roles and groups",
				slog.String("userUUID", user.UUID.String()),
				slog.Any("error", err))
			return
		}
		// generate the group name to project IDs map
		groupNameProjectIDsMap, err :=
			lagoon.GroupNameProjectIDsMap(ctx, l, k, userGroups)
		if err != nil {
			log.Error("couldn't generate group name to project IDs map",
				slog.Any("error", err))
			return
		}
		log.Debug("keycloak user attributes",
			slog.Any("realmRoles", realmRoles),
			slog.Any("userGroups", userGroups),
			slog.Any("groupNameProjectIDsMap", groupNameProjectIDsMap),
			slog.String("userUUID", user.UUID.String()),
		)
		// check permission
		ok := p.UserCanSSHToEnvironment(
			ctx, env, realmRoles, userGroups, groupNameProjectIDsMap)
		var logMsg string
		if ok {
			logMsg = "SSH access authorized"
		} else {
			logMsg = "SSH access not authorized"
		}
		log.Info(logMsg,
			slog.Int("environmentID", env.ID),
			slog.Int("projectID", env.ProjectID),
			slog.String("environmentName", env.Name),
			slog.String("projectName", env.ProjectName),
			slog.String("userUUID", user.UUID.String()),
		)
		if err = c.Publish(replySubject, ok); err != nil {
			log.Error("couldn't publish reply",
				slog.String("userUUID", user.UUID.String()),
				slog.Any("error", err))
		}
	}
}
