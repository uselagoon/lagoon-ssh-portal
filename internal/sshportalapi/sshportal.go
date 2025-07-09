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
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"go.opentelemetry.io/otel"
)

var (
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshportal_api_requests_total",
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
	ldb LagoonDBService,
) nats.MsgHandler {
	return func(msg *nats.Msg) {
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
		env, err := ldb.EnvironmentByNamespaceName(ctx, query.NamespaceName)
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
		user, err := ldb.UserBySSHFingerprint(ctx, query.SSHFingerprint)
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
		if err := ldb.SSHKeyUsed(ctx, query.SSHFingerprint, time.Now()); err != nil {
			log.Error("couldn't update ssh key last used",
				slog.Any("error", err))
			return
		}
		// check permission
		ok, err := p.UserCanSSHToEnvironment(
			ctx, log, *user.UUID, env.ProjectID, env.Type)
		if err != nil {
			log.Error("couldn't check if user can ssh to environment",
				slog.Any("error", err))
		}
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
			slog.String("environmentType", env.Type.String()),
			slog.String("environmentName", env.Name),
			slog.Int("projectID", env.ProjectID),
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
