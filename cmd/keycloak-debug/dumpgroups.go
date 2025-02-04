package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/davecgh/go-spew/spew"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
)

// DumpGroupsCmd represents the dump-groups command.
type DumpGroupsCmd struct {
	KeycloakBaseURL      string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakInsecureTLS  bool   `kong:"env='KEYCLOAK_INSECURE_TLS',help='Keycloak Insecure TLS'"`
	KeycloakClientID     string `kong:"default='service-api',env='KEYCLOAK_SERVICE_API_CLIENT_ID',help='Keycloak OAuth2 Client ID'"`
	KeycloakClientSecret string `kong:"required,env='KEYCLOAK_SERVICE_API_CLIENT_SECRET',help='Keycloak OAuth2 Client Secret'"`
	KeycloakRateLimit    int    `kong:"default=10,env='KEYCLOAK_RATE_LIMIT',help='Keycloak API Rate Limit (requests/second)'"`
}

// Run the serve command to ssh-portal API requests.
func (cmd *DumpGroupsCmd) Run(log *slog.Logger) error {
	// get main process context, which cancels on SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	// init keycloak client
	k, err := keycloak.NewClient(ctx, log,
		cmd.KeycloakBaseURL,
		cmd.KeycloakClientID,
		cmd.KeycloakClientSecret,
		cmd.KeycloakRateLimit,
		cmd.KeycloakInsecureTLS)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak client: %v", err)
	}
	groupMap, err := k.TopLevelGroupNameGroupIDMap(ctx)
	if err != nil {
		return fmt.Errorf("couldn't get keycloak group map: %v", err)
	}
	spew.Dump(groupMap)
	return nil
}
