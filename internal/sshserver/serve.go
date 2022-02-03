package sshserver

import (
	"context"
	"fmt"
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"go.uber.org/zap"
)

// Serve contains the main ssh session logic
func Serve(ctx context.Context, log *zap.Logger, nc *nats.Conn,
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
	return srv.Serve(l)
}
