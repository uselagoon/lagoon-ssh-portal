package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/permission"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

const (
	subject = "lagoon.serviceapi.sshportal"
	queue   = "service-api"
	pkgName = "github.com/uselagoon/ssh-portal/internal/server"
)

var (
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "serviceapi_requests_total",
		Help: "The total number of requests received",
	})
)

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	EnvironmentByNamespaceName(context.Context, string) (*lagoondb.Environment, error)
	UserBySSHFingerprint(context.Context, string) (*lagoondb.User, error)
}

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	UserRolesAndGroups(context.Context, *uuid.UUID) ([]string, []string, map[string][]int, error)
}

func sshportal(ctx context.Context, log *zap.Logger, c *nats.EncodedConn,
	l LagoonDBService, k KeycloakService) nats.Handler {
	return func(_, replySubject string, query *lagoondb.SSHAccessQuery) {
		var realmRoles, userGroups []string
		var groupProjectIDs map[string][]int
		// set up tracing and update metrics
		ctx, span := otel.Tracer(pkgName).Start(ctx, subject)
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
				return
			}
			log.Error("couldn't query environment",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// get the user
		user, err := l.UserBySSHFingerprint(ctx, query.SSHFingerprint)
		if err != nil {
			if !errors.Is(err, lagoondb.ErrNoResult) {
				log.Error("couldn't query user", zap.Any("query", query),
					zap.Error(err))
				return
			}
			log.Debug("unknown SSH Fingerprint",
				zap.Any("query", query), zap.Error(err))
			if err = c.Publish(replySubject, false); err != nil {
				log.Error("couldn't publish reply",
					zap.Any("query", query),
					zap.Bool("reply value", false),
					zap.String("user UUID", user.UUID.String()),
					zap.Error(err))
			}
			return
		}
		// get the user roles and groups
		realmRoles, userGroups, groupProjectIDs, err =
			k.UserRolesAndGroups(ctx, user.UUID)
		if err != nil {
			log.Error("couldn't query user roles and groups",
				zap.Any("query", query),
				zap.String("user UUID", user.UUID.String()),
				zap.Error(err))
			return
		}
		log.Debug("keycloak query response",
			zap.Strings("realm roles", realmRoles),
			zap.Strings("user groups", userGroups),
			zap.Any("group project IDs", groupProjectIDs),
			zap.String("user UUID", user.UUID.String()))
		// calculate permission
		ok := permission.UserCanSSHToEnvironment(ctx, env, realmRoles, userGroups,
			groupProjectIDs)
		if err = c.Publish(replySubject, ok); err != nil {
			log.Error("couldn't publish reply",
				zap.Any("query", query),
				zap.Bool("reply value", ok),
				zap.String("user UUID", user.UUID.String()),
				zap.Error(err))
		}
	}
}

// ServeNATS serviceapi NATS requests.
func ServeNATS(ctx context.Context, log *zap.Logger, l LagoonDBService,
	k KeycloakService, natsURL string) error {
	// setup synchronisation
	wg := sync.WaitGroup{}
	wg.Add(1)
	// connect to NATS server
	nc, err := nats.Connect(natsURL,
		// synchronise exiting ServeNATS()
		nats.ClosedHandler(func(_ *nats.Conn) {
			wg.Done()
		}))
	if err != nil {
		return fmt.Errorf("couldn't connect to NATS server: %v", err)
	}
	c, err := nats.NewEncodedConn(nc, "json")
	if err != nil {
		return fmt.Errorf("couldn't get encoded conn: %v", err)
	}
	defer c.Close()
	// set up request/response callback
	_, err = c.QueueSubscribe(subject, queue, sshportal(ctx, log, c, l, k))
	if err != nil {
		return fmt.Errorf("couldn't subscribe to queue: %v", err)
	}
	// wait for context cancellation
	<-ctx.Done()
	// drain and log errors
	if err := c.Drain(); err != nil {
		log.Error("couldn't drain connection", zap.Error(err))
	}
	// wait for connection to close
	wg.Wait()
	return nil
}
