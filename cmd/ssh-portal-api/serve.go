package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/go-sql-driver/mysql"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	APIDBAddress         string `kong:"required,env='API_DB_ADDRESS',help='Lagoon API DB Address (host[:port])'"`
	APIDBDatabase        string `kong:"default='infrastructure',env='API_DB_DATABASE',help='Lagoon API DB Database Name'"`
	APIDBPassword        string `kong:"required,env='API_DB_PASSWORD',help='Lagoon API DB Password'"`
	APIDBUsername        string `kong:"default='api',env='API_DB_USERNAME',help='Lagoon API DB Username'"`
	KeycloakBaseURL      string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakClientID     string `kong:"default='service-api',env='KEYCLOAK_SERVICE_API_CLIENT_ID',help='Keycloak OAuth2 Client ID'"`
	KeycloakClientSecret string `kong:"required,env='KEYCLOAK_SERVICE_API_CLIENT_SECRET',help='Keycloak OAuth2 Client Secret'"`
	NATSURL              string `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
}

// Run the serve command to ssh-portal API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// instrumentation requires a separate context because deferred Shutdown()
	// will exit immediately if the context is already done.
	ictx := context.Background()
	// init metrics
	m := metrics.NewServer(log, ":9911")
	defer m.Shutdown(ictx) //nolint:errcheck
	// get main process context, which cancels on SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	// init lagoon DB client
	dbConf := mysql.NewConfig()
	dbConf.Addr = cmd.APIDBAddress
	dbConf.DBName = cmd.APIDBDatabase
	dbConf.Net = "tcp"
	dbConf.Passwd = cmd.APIDBPassword
	dbConf.User = cmd.APIDBUsername
	l, err := lagoondb.NewClient(ctx, dbConf.FormatDSN())
	if err != nil {
		return fmt.Errorf("couldn't init lagoon DBClient: %v", err)
	}
	// init keycloak client
	k, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakClientID, cmd.KeycloakClientSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak Client: %v", err)
	}
	// start serving NATS requests
	return sshportalapi.ServeNATS(ctx, stop, log, l, k, cmd.NATSURL)
}
