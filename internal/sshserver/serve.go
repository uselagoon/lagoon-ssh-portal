// Package sshserver is the SSH server component of the Lagoon ssh-portal.
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
	gossh "golang.org/x/crypto/ssh"
)

// disableSHA1Kex returns a ServerConfig which relies on default for everything
// except key exchange algorithms. There it removes the SHA1 based algorithms.
func disableSHA1Kex(ctx ssh.Context) *gossh.ServerConfig {
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

// Serve contains the main ssh session logic
func Serve(ctx context.Context, log *zap.Logger, nc *nats.EncodedConn,
	l net.Listener, c *k8s.Client, hostKeys [][]byte, logAccessEnabled bool) error {
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
