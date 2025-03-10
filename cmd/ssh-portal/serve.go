package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/uselagoon/ssh-portal/internal/bus"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	"golang.org/x/sync/errgroup"
)

const (
	metricsPort = ":9912"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	NATSServer         string        `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
	SSHServerPort      uint          `kong:"default='2222',env='SSH_SERVER_PORT',help='Port the SSH server will listen on for SSH client connections'"`
	HostKeyECDSA       string        `kong:"env='HOST_KEY_ECDSA',help='PEM encoded ECDSA host key'"`
	HostKeyED25519     string        `kong:"env='HOST_KEY_ED25519',help='PEM encoded Ed25519 host key'"`
	HostKeyRSA         string        `kong:"env='HOST_KEY_RSA',help='PEM encoded RSA host key'"`
	LogAccessEnabled   bool          `kong:"env='LOG_ACCESS_ENABLED',help='Allow any user who can SSH into a pod to also access its logs'"`
	Banner             string        `kong:"env='BANNER',help='Text sent to remote users before authentication'"`
	ConcurrentLogLimit uint          `kong:"default='32',env='CONCURRENT_LOG_LIMIT',help='Maximum number of concurrent log sessions'"`
	LogTimeLimit       time.Duration `kong:"default='4h',env='LOG_TIME_LIMIT',help='Maximum lifetime of each logs session'"`
}

// Run the serve command to handle SSH connection requests.
func (cmd *ServeCmd) Run(log *slog.Logger) error {
	// get main process context, which cancels on SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	// get nats client
	nc, err := bus.NewNATSClient(cmd.NATSServer, log, cancel)
	if err != nil {
		return fmt.Errorf("couldn't get nats client: %v", err)
	}
	defer nc.Close()
	// start listening on TCP port
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cmd.SSHServerPort))
	if err != nil {
		return fmt.Errorf("couldn't listen on port %d: %v", cmd.SSHServerPort, err)
	}
	defer l.Close()
	// get kubernetes client
	c, err := k8s.NewClient(cmd.ConcurrentLogLimit, cmd.LogTimeLimit)
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
	// set up goroutine handler
	eg, ctx := errgroup.WithContext(ctx)
	// start the metrics server
	metrics.Serve(ctx, eg, metricsPort)
	// start serving SSH token requests
	eg.Go(func() error {
		// start serving SSH connection requests
		return sshserver.Serve(
			ctx,
			log,
			nc,
			l,
			c,
			hostkeys,
			cmd.LogAccessEnabled,
			cmd.Banner,
		)
	})
	return eg.Wait()
}
