package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/go-sql-driver/mysql"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	"golang.org/x/sync/errgroup"
)

const (
	metricsPort = ":9911"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	APIDBAddress         string `kong:"required,env='API_DB_ADDRESS',help='Lagoon API DB Address (host[:port])'"`
	APIDBDatabase        string `kong:"default='infrastructure',env='API_DB_DATABASE',help='Lagoon API DB Database Name'"`
	APIDBPassword        string `kong:"required,env='API_DB_PASSWORD',help='Lagoon API DB Password'"`
	APIDBUsername        string `kong:"default='api',env='API_DB_USERNAME',help='Lagoon API DB Username'"`
	BlockDeveloperSSH    bool   `kong:"env='BLOCK_DEVELOPER_SSH',help='Disallow Developer SSH access'"`
	KeycloakBaseURL      string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakInsecureTLS  bool   `kong:"env='KEYCLOAK_INSECURE_TLS',help='Keycloak Insecure TLS'"`
	KeycloakClientID     string `kong:"default='service-api',env='KEYCLOAK_SERVICE_API_CLIENT_ID',help='Keycloak OAuth2 Client ID'"`
	KeycloakClientSecret string `kong:"required,env='KEYCLOAK_SERVICE_API_CLIENT_SECRET',help='Keycloak OAuth2 Client Secret'"`
	KeycloakRateLimit    int    `kong:"default=10,env='KEYCLOAK_RATE_LIMIT',help='Keycloak API Rate Limit (requests/second)'"`
	KeycloakPageSize     int    `kong:"default=1000,env='KEYCLOAK_PAGE_SIZE',help='Keycloak API Page Size'"`
	NATSURL              string `kong:"required,env='NATS_URL',help='NATS server URL (nats://... or tls://...)'"`
}

// Run the serve command to ssh-portal API requests.
func (cmd *ServeCmd) Run(log *slog.Logger) error {
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
	ldb, err := lagoondb.NewClient(ctx, dbConf.FormatDSN())
	if err != nil {
		return fmt.Errorf("couldn't init lagoondb client: %v", err)
	}
	// init keycloak client
	k, err := keycloak.NewClient(ctx, log,
		cmd.KeycloakBaseURL,
		cmd.KeycloakClientID,
		cmd.KeycloakClientSecret,
		cmd.KeycloakRateLimit,
		cmd.KeycloakPageSize,
		cmd.KeycloakInsecureTLS)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak client: %v", err)
	}
	// init RBAC permission engine
	var p *rbac.Permission
	if cmd.BlockDeveloperSSH {
		p = rbac.NewPermission(k, ldb, rbac.BlockDeveloperSSH())
	} else {
		p = rbac.NewPermission(k, ldb)
	}
	// set up goroutine handler
	eg, ctx := errgroup.WithContext(ctx)
	// start the metrics server
	metrics.Serve(ctx, eg, metricsPort)
	// start serving SSH token requests
	eg.Go(func() error {
		// start serving NATS requests
		return sshportalapi.ServeNATS(ctx, stop, log, p, ldb, cmd.NATSURL)
	})
	return eg.Wait()
}
