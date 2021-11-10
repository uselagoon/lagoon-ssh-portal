package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/serviceapi"
	"go.uber.org/zap"

	_ "github.com/go-sql-driver/mysql"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	NATSServer           string `kong:"required,help='NATS server URL (nats://... or tls://...)'"`
	APIDB                string `kong:"required,help='Lagoon API Database DSN (https://github.com/go-sql-driver/mysql#dsn-data-source-name)'"`
	JWTSecret            string `kong:"required,help='JWT Symmetric Secret'"`
	KeycloakBaseURL      string `kong:"required,help='Keycloak Base URL'"`
	KeycloakClientID     string `kong:"default='service-api',help='Keycloak OAuth2 Client ID'"`
	KeycloakClientSecret string `kong:"required,help='Keycloak OAuth2 Client Secret'"`
}

// getContext starts a goroutine to handle ^C gracefully, and returns a context
// with a "cancel" function which cleans up the signal handling and ensures the
// goroutine exits. This "cancel" function should be deferred in Run().
func getContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		select {
		case <-signalChan:
			cancel()
		case <-ctx.Done():
		}
		<-signalChan
		os.Exit(130) // https://tldp.org/LDP/abs/html/exitcodes.html
	}()
	return ctx, func() { signal.Stop(signalChan); cancel() }
}

// Run the serve command to service API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	ctx, cancel := getContext()
	defer cancel()
	// init lagoon DB client
	l, err := lagoondb.NewClient(ctx, cmd.APIDB)
	if err != nil {
		return fmt.Errorf("couldn't init lagoon DBClient: %v", err)
	}
	// init keycloak client
	k, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakClientID, cmd.KeycloakClientSecret, cmd.JWTSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak Client: %v", err)
	}
	// start serving NATS requests
	return serviceapi.ServeNATS(ctx, log, l, k, cmd.NATSServer)
}
