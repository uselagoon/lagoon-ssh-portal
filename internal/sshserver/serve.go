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
	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/k8s"
	gossh "golang.org/x/crypto/ssh"
)

// default server shutdown timeout once the top-level context is cancelled
// (e.g. via signal)
const shutdownTimeout = 8 * time.Second

// disableSHA1Kex returns a ServerConfig which relies on default for everything
// except key exchange algorithms. There it removes the SHA1 based algorithms.
//
// This works around https://github.com/golang/go/issues/59593
func disableSHA1Kex(_ ssh.Context) *gossh.ServerConfig {
	c := gossh.ServerConfig{}
	c.Config.KeyExchanges = []string{
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
	nc *nats.EncodedConn,
	l net.Listener,
	c *k8s.Client,
	hostKeys [][]byte,
	logAccessEnabled bool,
) error {
	srv := ssh.Server{
		Handler: sessionHandler(log, c, false, logAccessEnabled),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": ssh.SubsystemHandler(sessionHandler(log, c, true, logAccessEnabled)),
		},
		PublicKeyHandler:     pubKeyAuth(log, nc, c),
		ServerConfigCallback: disableSHA1Kex,
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
	if err := srv.Serve(l); !errors.Is(ssh.ErrServerClosed, err) {
		return err
	}
	return nil
}
