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

// disableInsecureAlgos returns a ServerConfig which removes the "insecure"
// algorithms from the default list of MACs and KexAlgos.
//
// This works around https://github.com/golang/go/issues/59593
func disableInsecureAlgos(_ ssh.Context) *gossh.ServerConfig {
	c := gossh.ServerConfig{}
	// x/crypto@v0.46.0 defaultMACs, minus InsecureHMACSHA196
	c.MACs = []string{
		gossh.HMACSHA256ETM,
		gossh.HMACSHA512ETM,
		gossh.HMACSHA256,
		gossh.HMACSHA512,
		gossh.HMACSHA1,
	}
	// x/crypto@v0.46.0 defaultKexAlgos, minus InsecureKeyExchangeDH14SHA1
	c.KeyExchanges = []string{
		gossh.KeyExchangeMLKEM768X25519,
		gossh.KeyExchangeCurve25519,
		gossh.KeyExchangeECDHP256,
		gossh.KeyExchangeECDHP384,
		gossh.KeyExchangeECDHP521,
		gossh.KeyExchangeDH14SHA256,
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
		ServerConfigCallback: disableInsecureAlgos,
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
