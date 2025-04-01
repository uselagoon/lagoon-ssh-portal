// Package sshserver is the SSH server component of the Lagoon ssh-portal.
package sshserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	gossh "golang.org/x/crypto/ssh"
)

// default server shutdown timeout once the top-level context is cancelled
// (e.g. via signal)
const shutdownTimeout = 8 * time.Second

// NATSService represents a NATS RPC service.
type NATSService interface {
	KeyCanAccessEnvironment(string, string, string, int, int) (bool, error)
}

// disableSHA1Kex returns a ServerConfig which relies on default for everything
// except key exchange algorithms. There it removes the SHA1 based algorithms.
//
// This works around https://github.com/golang/go/issues/59593
func disableSHA1Kex(_ ssh.Context) *gossh.ServerConfig {
	c := gossh.ServerConfig{}
	c.KeyExchanges = []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
	}
	return &c
}

// Serve implements the ssh server logic.
func Serve(
	ctx context.Context,
	log *slog.Logger,
	nats NATSService,
	l net.Listener,
	c *k8s.Client,
	hostKeys [][]byte,
	logAccessEnabled bool,
	banner string,
) error {
	srv := ssh.Server{
		Handler: sessionHandler(log, c, false, logAccessEnabled),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": ssh.SubsystemHandler(sessionHandler(log, c, true, logAccessEnabled)),
		},
		PublicKeyHandler:     pubKeyHandler(log, nats, c),
		ServerConfigCallback: disableSHA1Kex,
		Banner:               banner,
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
			log.Warn("couldn't shutdown cleanly", slog.Any("error", err))
		}
	}()
	if err := srv.Serve(l); !errors.Is(err, ssh.ErrServerClosed) {
		return err
	}
	return nil
}
