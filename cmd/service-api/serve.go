package main

import (
	"context"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/serviceapi"
	"github.com/uselagoon/ssh-portal/internal/signalctx"
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
	NATSUsername         string `kong:"default='service-api',env='NATS_USERNAME',help='NATS Username'"`
	NATSPassword         string `kong:"default='service-api',env='NATS_PASSWORD',help='NATS Password'"`
}

// Run the serve command to service API requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	// instrumentation requires a separate context because deferred Shutdown()
	// will exit immediately if the context is already done.
	ictx := context.Background()
	// init metrics
	m := metrics.NewServer(log, ":9911")
	defer m.Shutdown(ictx) //nolint:errcheck
	// get main process context
	ctx, cancel := signalctx.GetContext()
	defer cancel()
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
	return serviceapi.ServeNATS(ctx, log, l, k, cmd.NATSURL, cmd.NATSUsername, cmd.NATSPassword)
}
