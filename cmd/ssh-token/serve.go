package main

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"syscall"

	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/sshtoken"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	APIGraphqlEndpoint        string `kong:"required,env='API_GRAPHQL_ENDPOINT',help='Lagoon API server URL (http://.../graphql or https://.../graphql)'"`
	APIJWTToken               string `kong:"default='super-secret-string',env='API_JWT_TOKEN',help='Lagoon API JWT Token'"`
	APIAudience               string `kong:"default='api.dev',env='API_JWT_AUDIENCE',help='Lagoon API JWT Audience'"`
	HostKeyECDSA              string `kong:"env='HOST_KEY_ECDSA',help='PEM encoded ECDSA host key'"`
	HostKeyED25519            string `kong:"env='HOST_KEY_ED25519',help='PEM encoded Ed25519 host key'"`
	HostKeyRSA                string `kong:"env='HOST_KEY_RSA',help='PEM encoded RSA host key'"`
	KeycloakBaseURL           string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakTokenClientID     string `kong:"default='auth-server',env='KEYCLOAK_AUTH_SERVER_CLIENT_ID',help='Keycloak auth-server OAuth2 Client ID'"`
	KeycloakTokenClientSecret string `kong:"required,env='KEYCLOAK_AUTH_SERVER_CLIENT_SECRET',help='Keycloak auth-server OAuth2 Client Secret'"`
	SSHServerPort             uint   `kong:"default='2222',env='SSH_SERVER_PORT',help='Port the SSH server will listen on for SSH client connections'"`
}

// Run the serve command to ssh-portal API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// metrics needs a separate context because deferred Shutdown() will exit
	// immediately the context is done, which is the case for ctx on SIGTERM.
	m := metrics.NewServer(log, ":9948")
	defer m.Shutdown(context.Background()) //nolint:errcheck
	// get main process context, which cancels on SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	// init lagoon config
	lconf := lagoon.LagoonClientConfig{
		APIGraphqlEndpoint: cmd.APIGraphqlEndpoint,
		JWTToken:           cmd.APIJWTToken,
		JWTAudience:        cmd.APIAudience,
	}
	// init token / auth-server keycloak client
	keycloakToken, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakTokenClientID, cmd.KeycloakTokenClientSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak token client: %v", err)
	}
	// start listening on TCP port
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cmd.SSHServerPort))
	if err != nil {
		return fmt.Errorf("couldn't listen on port %d: %v", cmd.SSHServerPort, err)
	}
	// check for persistent host key arguments
	var hostkeys [][]byte
	for _, hk := range []string{cmd.HostKeyECDSA, cmd.HostKeyED25519,
		cmd.HostKeyRSA} {
		if len(hk) > 0 {
			hostkeys = append(hostkeys, []byte(hk))
		}
	}
	// start serving SSH token requests
	return sshtoken.Serve(ctx, log, l, keycloakToken, lconf,
		hostkeys)
}
