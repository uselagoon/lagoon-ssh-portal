package serviceapi

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"go.uber.org/zap"
)

const (
	queue   = "serviceapi"
	pkgName = "github.com/uselagoon/ssh-portal/internal/serviceapi"
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
	// set up request/response callback for sshportal
	_, err = c.QueueSubscribe(SubjectSSHAccessQuery, queue, sshportal(ctx, log, c, l, k))
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
