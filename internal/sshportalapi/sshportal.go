package sshportalapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/bus"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"go.opentelemetry.io/otel"
)

var (
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportalapi_requests_total",
		Help: "The total number of ssh-portal-api requests received",
	})
)

var (
	falseResponse = []byte(`false`)
	trueResponse  = []byte(`true`)
)

func sshportal(
	ctx context.Context,
	log *slog.Logger,
	c *nats.Conn,
	p *rbac.Permission,
	l LagoonDBService,
	k KeycloakService,
) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var realmRoles, userGroups []string
		// set up tracing and update metrics
		ctx, span := otel.Tracer(pkgName).Start(ctx, bus.SubjectSSHAccessQuery)
		defer span.End()
		requestsCounter.Inc()
		var query bus.SSHAccessQuery
		if err := json.Unmarshal(msg.Data, &query); err != nil {
			log.Warn("couldn't unmarshal query", slog.Any("query", msg.Data))
			return
		}
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
				if err = c.Publish(msg.Reply, falseResponse); err != nil {
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
			if err = c.Publish(msg.Reply, falseResponse); err != nil {
				log.Error("couldn't publish reply", slog.Any("error", err))
			}
			return
		}
		// get the user
		user, err := l.UserBySSHFingerprint(ctx, query.SSHFingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint", slog.Any("error", err))
				if err = c.Publish(msg.Reply, falseResponse); err != nil {
					log.Error("couldn't publish reply", slog.Any("error", err))
				}
				return
			}
			log.Error("couldn't query user by ssh fingerprint", slog.Any("error", err))
			return
		}
		// update last_used
		if err := l.SSHKeyUsed(ctx, query.SSHFingerprint, time.Now()); err != nil {
			log.Error("couldn't update ssh key last used: %v",
				slog.Any("error", err))
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
		var response []byte
		if ok {
			logMsg = "SSH access authorized"
			response = trueResponse
		} else {
			logMsg = "SSH access not authorized"
			response = falseResponse
		}
		log.Info(logMsg,
			slog.Int("environmentID", env.ID),
			slog.Int("projectID", env.ProjectID),
			slog.String("environmentName", env.Name),
			slog.String("projectName", env.ProjectName),
			slog.String("userUUID", user.UUID.String()),
		)
		if err = c.Publish(msg.Reply, response); err != nil {
			log.Error("couldn't publish reply",
				slog.String("userUUID", user.UUID.String()),
				slog.Any("error", err))
		}
	}
}
