package main

import (
	"context"
	"fmt"
	"net"

	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/signalctx"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	NATSServer     string `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
	SSHServerPort  uint   `kong:"default='2222',env='SSH_SERVER_PORT',help='Port the SSH server will listen on for SSH client connections'"`
	HostKeyECDSA   string `kong:"env='HOST_KEY_ECDSA',help='PEM encoded ECDSA host key'"`
	HostKeyED25519 string `kong:"env='HOST_KEY_ED25519',help='PEM encoded Ed25519 host key'"`
	HostKeyRSA     string `kong:"env='HOST_KEY_RSA',help='PEM encoded RSA host key'"`
}

// Run the serve command to service API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// instrumentation requires a separate context because deferred Shutdown()
	// will exit immediately if the context is already done.
	ictx := context.Background()
	// init metrics
	m := metrics.NewServer(log, ":9912")
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
	// check for persistent host key arguments
	var hostkeys [][]byte
	for _, hk := range []string{cmd.HostKeyECDSA, cmd.HostKeyED25519, cmd.HostKeyRSA} {
		if len(hk) > 0 {
			hostkeys = append(hostkeys, []byte(hk))
		}
	}
	// start serving SSH connection requests
	return sshserver.Serve(ctx, log, nc, l, c, hostkeys)
}
