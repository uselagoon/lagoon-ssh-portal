// Package sshportalapi implements the lagoon-core component of the ssh-portal
// service.
package sshportalapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/bus"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/rbac"
)

const (
	queue   = "sshportalapi"
	pkgName = "github.com/uselagoon/ssh-portal/internal/sshportalapi"
)

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	EnvironmentByNamespaceName(context.Context, string) (*lagoondb.Environment, error)
	UserBySSHFingerprint(context.Context, string) (*lagoondb.User, error)
	SSHKeyUsed(context.Context, string, time.Time) error
}

// ServeNATS sshportalapi NATS requests.
func ServeNATS(
	ctx context.Context,
	stop context.CancelFunc,
	log *slog.Logger,
	p *rbac.Permission,
	ldb LagoonDBService,
	natsURL string,
) error {
	// setup synchronisation
	wg := sync.WaitGroup{}
	wg.Add(1)
	// connect to NATS server
	nc, err := nats.Connect(natsURL,
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
	defer nc.Close()
	// configure callback
	_, err = nc.QueueSubscribe(
		bus.SubjectSSHAccessQuery,
		queue,
		sshportal(ctx, log, nc, p, ldb),
	)
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
