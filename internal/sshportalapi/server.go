// Package sshportalapi implements the lagoon-core component of the ssh-portal
// service.
package sshportalapi

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"go.uber.org/zap"
)

const (
	queue   = "sshportalapi"
	pkgName = "github.com/uselagoon/ssh-portal/internal/sshportalapi"
)

// KeycloakTokenService provides methods for querying the Keycloak API for user
// access tokens.
type KeycloakTokenService interface {
	UserAccessToken(context.Context, *uuid.UUID) (string, error)
}

// ServeNATS sshportalapi NATS requests.
func ServeNATS(ctx context.Context, stop context.CancelFunc, log *zap.Logger,
	k KeycloakTokenService, lconf lagoon.LagoonClientConfig, natsURL string) error {
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
			log.Warn("nats disconnected", zap.Error(err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info("nats reconnected", zap.String("url", nc.ConnectedUrl()))
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
		sshportal(ctx, log, nc, k, lconf))
	if err != nil {
		return fmt.Errorf("couldn't subscribe to queue: %v", err)
	}
	// wait for context cancellation
	<-ctx.Done()
	// drain and log errors
	if err := nc.Drain(); err != nil {
		log.Warn("couldn't drain connection", zap.Error(err))
	}
	// wait for connection to close
	wg.Wait()
	return nil
}
