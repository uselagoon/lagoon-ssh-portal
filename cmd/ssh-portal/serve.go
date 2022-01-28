package main

import (
	"context"
	"fmt"
	"net"

	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/signalctx"
	"github.com/uselagoon/ssh-portal/internal/sshportal"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	NATSServer    string `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
	SSHServerPort uint   `kong:"default='2222',env='SSH_SERVER_PORT',help='Port the SSH server will listen on for SSH client connections'"`
}

// Run the serve command to service API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// instrumentation requires a separate context because deferred Shutdown()
	// will exit immediately if the context is already done.
	ictx := context.Background()
	// init metrics
	m := metrics.NewServer(log)
	defer m.Shutdown(ictx) //nolint:errcheck
	// get main process context
	ctx, cancel := signalctx.GetContext()
	defer cancel()
	// get nats server connection
	nc, err := nats.Connect(cmd.NATSServer)
	if err != nil {
		return fmt.Errorf("couldn't connect to NATS server: %v", err)
	}
	// start listening on TCP port
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cmd.SSHServerPort))
	if err != nil {
		return fmt.Errorf("couldn't listen on port %d: %v", cmd.SSHServerPort, err)
	}
	// get kubernetes client
	c, err := k8s.NewClient()
	if err != nil {
		return fmt.Errorf("couldn't create k8s client: %v", err)
	}
	// start serving SSH connection requests
	return sshportal.Serve(ctx, log, nc, l, c)
}
