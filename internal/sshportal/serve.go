package sshportal

import (
	"context"
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"go.uber.org/zap"
)

// Serve contains the main ssh session logic
func Serve(ctx context.Context, log *zap.Logger, nc *nats.Conn,
	l net.Listener, c *k8s.Client) error {
	return ssh.Serve(l, sessionHandler(log, c),
		ssh.PublicKeyAuth(pubKeyAuth(log, nc, c)))
}
