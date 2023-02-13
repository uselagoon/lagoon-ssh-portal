// Package sshtoken is the SSH token generation component of Lagoon.
package sshtoken

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/permission"
	"go.uber.org/zap"
)

// give an 8 second deadline to shut down cleanly.
const shutdownTimeout = 8 * time.Second

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	EnvironmentByNamespaceName(context.Context, string) (*lagoondb.Environment, error)
	UserBySSHFingerprint(context.Context, string) (*lagoondb.User, error)
	SSHEndpointByEnvironmentID(context.Context, int) (string, string, error)
}

// Serve contains the main ssh session logic
func Serve(ctx context.Context, log *zap.Logger, l net.Listener,
	p *permission.Permission, ldb *lagoondb.Client,
	keycloakToken, keycloakPermission *keycloak.Client,
	hostKeys [][]byte) error {
	srv := ssh.Server{
		Handler:          sessionHandler(log, p, keycloakToken, keycloakPermission, ldb),
		PublicKeyHandler: pubKeyAuth(log, ldb),
	}
	for _, hk := range hostKeys {
		if err := srv.SetOption(ssh.HostKeyPEM(hk)); err != nil {
			return fmt.Errorf("invalid host key: %v", err)
		}
	}
	go func() {
		// As soon as the top level context is cancelled, shut down the server.
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Warn("couldn't shutdown cleanly", zap.Error(err))
		}
	}()
	if err := srv.Serve(l); !errors.Is(ssh.ErrServerClosed, err) {
		return err
	}
	return nil
}
