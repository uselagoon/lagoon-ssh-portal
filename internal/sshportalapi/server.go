// Package sshportalapi implements the lagoon-core component of the ssh-portal
// service.
package sshportalapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
)

const (
	queue   = "sshportalapi"
	pkgName = "github.com/uselagoon/ssh-portal/internal/sshportalapi"
)

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	lagoon.DBService
	EnvironmentByNamespaceName(context.Context, string) (*lagoondb.Environment, error)
	UserBySSHFingerprint(context.Context, string) (*lagoondb.User, error)
}

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	lagoon.KeycloakService
	UserRolesAndGroups(context.Context, *uuid.UUID) ([]string, []string, error)
}

// ServeNATS sshportalapi NATS requests.
func ServeNATS(ctx context.Context, stop context.CancelFunc, log *slog.Logger,
	p *rbac.Permission, l LagoonDBService, k KeycloakService, natsURL string) error {
	// setup synchronisation
	wg := sync.WaitGroup{}
	wg.Add(1)
	// connect to NATS server
	nconn, err := nats.Connect(natsURL,
		nats.Name("ssh-portal-api"),
		// synchronise exiting ServeNATS()
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Error("nats connection closed")
			stop()
			wg.Done()
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("nats disconnected", slog.Any("error", err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info("nats reconnected", slog.String("url", nc.ConnectedUrl()))
		}))
	if err != nil {
		return fmt.Errorf("couldn't connect to NATS server: %v", err)
	}
	nc, err := nats.NewEncodedConn(nconn, "json")
	if err != nil {
		return fmt.Errorf("couldn't get encoded conn: %v", err)
	}
	defer nc.Close()
	// set up request/response callback for sshportal
	_, err = nc.QueueSubscribe(SubjectSSHAccessQuery, queue,
		sshportal(ctx, log, nc, p, l, k))
	if err != nil {
		return fmt.Errorf("couldn't subscribe to queue: %v", err)
	}
	// wait for context cancellation
	<-ctx.Done()
	// drain and log errors
	if err := nc.Drain(); err != nil {
		log.Warn("couldn't drain connection", slog.Any("error", err))
	}
	// wait for connection to close
	wg.Wait()
	return nil
}
