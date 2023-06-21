package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	APIGraphqlEndpoint   string `kong:"required,env='API_GRAPHQL_ENDPOINT',help='Lagoon API server URL (http://.../graphql or https://.../graphql)'"`
	APIJWTToken          string `kong:"default='super-secret-string',env='API_JWT_TOKEN',help='Lagoon API JWT Token'"`
	APIAudience          string `kong:"default='api.dev',env='API_JWT_AUDIENCE',help='Lagoon API JWT Audience'"`
	KeycloakBaseURL      string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakClientID     string `kong:"default='service-api',env='KEYCLOAK_SERVICE_API_CLIENT_ID',help='Keycloak OAuth2 Client ID'"`
	KeycloakClientSecret string `kong:"required,env='KEYCLOAK_SERVICE_API_CLIENT_SECRET',help='Keycloak OAuth2 Client Secret'"`
	NATSURL              string `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
}

// Run the serve command to ssh-portal API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// metrics needs a separate context because deferred Shutdown() will exit
	// immediately the context is done, which is the case for ctx on SIGTERM.
	m := metrics.NewServer(log, ":9911")
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
	// init keycloak client
	k, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakClientID, cmd.KeycloakClientSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak Client: %v", err)
	}
	// start serving NATS requests
	return sshportalapi.ServeNATS(ctx, stop, log, k, lconf, cmd.NATSURL)
}
