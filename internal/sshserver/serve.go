package sshserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"go.uber.org/zap"
)

// Serve contains the main ssh session logic
func Serve(ctx context.Context, log *zap.Logger, nc *nats.EncodedConn,
	l net.Listener, c *k8s.Client, hostKeys [][]byte) error {
	srv := ssh.Server{
		Handler:          sessionHandler(log, c),
		PublicKeyHandler: pubKeyAuth(log, nc, c),
	}
	for _, hk := range hostKeys {
		if err := srv.SetOption(ssh.HostKeyPEM(hk)); err != nil {
			return fmt.Errorf("invalid host key: %v", err)
		}
	}
	go func() {
		// As soon as the top level context is cancelled, shut down the server.
		// Give an 8 second deadline to do this.
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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
