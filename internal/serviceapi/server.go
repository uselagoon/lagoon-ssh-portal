package serviceapi

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/permission"
	"go.uber.org/zap"
)

const (
	subject = "lagoon.serviceapi.sshportal"
	queue   = "service-api"
)

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	EnvironmentByNamespaceName(string) (*lagoondb.Environment, error)
	UserBySSHFingerprint(string) (*lagoondb.User, error)
}

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	UserRolesAndGroups(*uuid.UUID) ([]string, []string, map[string][]int, error)
}

func sshportal(log *zap.Logger, c *nats.EncodedConn, l LagoonDBService,
	k KeycloakService) nats.Handler {
	return func(subj, reply string, query *lagoondb.SSHAccessQuery) {
		// get the environment
		env, err := l.EnvironmentByNamespaceName(query.NamespaceName)
		if err != nil {
			log.Error("couldn't query environment",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// get the user
		user, err := l.UserBySSHFingerprint(query.SSHFingerprint)
		if err != nil {
			log.Error("couldn't query user",
				zap.Any("query", query), zap.Error(err))
			return
		}
		// get the user roles and groups
		realmRoles, userGroups, groupProjectIDs, err :=
			k.UserRolesAndGroups(user.UUID)
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
		ok := permission.UserCanSSHToEnvironment(env, realmRoles, userGroups,
			groupProjectIDs)
		if err = c.Publish(reply, ok); err != nil {
			log.Error("couldn't publish reply",
				zap.Any("query", query),
				zap.Bool("reply value", ok),
				zap.String("user UUID", user.UUID.String()),
				zap.Error(err))
			return
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
	_, err = c.QueueSubscribe(subject, queue, sshportal(log, c, l, k))
	if err != nil {
		return fmt.Errorf("couldn't subscribe to queue: %v", err)
	}
	// wait for context cancellation
	<-ctx.Done()
	// drain and ignore errors
	if err := c.Drain(); err != nil {
		log.Error("couldn't drain connection", zap.Error(err))
	}
	// wait for connection to close
	wg.Wait()
	return nil
}
