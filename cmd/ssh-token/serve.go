package main

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"syscall"

	"github.com/go-sql-driver/mysql"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/metrics"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"github.com/uselagoon/ssh-portal/internal/sshtoken"
	"go.uber.org/zap"
)

// ServeCmd represents the serve command.
type ServeCmd struct {
	APIDBAddress                   string `kong:"required,env='API_DB_ADDRESS',help='Lagoon API DB Address (host[:port])'"`
	APIDBDatabase                  string `kong:"default='infrastructure',env='API_DB_DATABASE',help='Lagoon API DB Database Name'"`
	APIDBPassword                  string `kong:"required,env='API_DB_PASSWORD',help='Lagoon API DB Password'"`
	APIDBUsername                  string `kong:"default='api',env='API_DB_USERNAME',help='Lagoon API DB Username'"`
	BlockDeveloperSSH              bool   `kong:"env='BLOCK_DEVELOPER_SSH',help='Disallow Developer SSH access'"`
	HostKeyECDSA                   string `kong:"env='HOST_KEY_ECDSA',help='PEM encoded ECDSA host key'"`
	HostKeyED25519                 string `kong:"env='HOST_KEY_ED25519',help='PEM encoded Ed25519 host key'"`
	HostKeyRSA                     string `kong:"env='HOST_KEY_RSA',help='PEM encoded RSA host key'"`
	KeycloakBaseURL                string `kong:"required,env='KEYCLOAK_BASE_URL',help='Keycloak Base URL'"`
	KeycloakPermissionClientID     string `kong:"default='service-api',env='KEYCLOAK_SERVICE_API_CLIENT_ID',help='Keycloak service-api OAuth2 Client ID'"`
	KeycloakPermissionClientSecret string `kong:"env='KEYCLOAK_SERVICE_API_CLIENT_SECRET',help='Keycloak service-api OAuth2 Client Secret'"`
	KeycloakTokenClientID          string `kong:"default='auth-server',env='KEYCLOAK_AUTH_SERVER_CLIENT_ID',help='Keycloak auth-server OAuth2 Client ID'"`
	KeycloakTokenClientSecret      string `kong:"required,env='KEYCLOAK_AUTH_SERVER_CLIENT_SECRET',help='Keycloak auth-server OAuth2 Client Secret'"`
	SSHServerPort                  uint   `kong:"default='2222',env='SSH_SERVER_PORT',help='Port the SSH server will listen on for SSH client connections'"`
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
	// init RBAC permission engine
	var p *rbac.Permission
	if cmd.BlockDeveloperSSH {
		p = rbac.NewPermission(rbac.BlockDeveloperSSH())
	} else {
		p = rbac.NewPermission()
	}
	// init lagoon DB client
	dbConf := mysql.NewConfig()
	dbConf.Addr = cmd.APIDBAddress
	dbConf.DBName = cmd.APIDBDatabase
	dbConf.Net = "tcp"
	dbConf.Passwd = cmd.APIDBPassword
	dbConf.User = cmd.APIDBUsername
	ldb, err := lagoondb.NewClient(ctx, dbConf.FormatDSN())
	if err != nil {
		return fmt.Errorf("couldn't init lagoonDB client: %v", err)
	}
	// init token / auth-server keycloak client
	keycloakToken, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakTokenClientID, cmd.KeycloakTokenClientSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak token client: %v", err)
	}
	// init permission / service-api keycloak client
	keycloakPermission, err := keycloak.NewClient(ctx, log, cmd.KeycloakBaseURL,
		cmd.KeycloakPermissionClientID, cmd.KeycloakPermissionClientSecret)
	if err != nil {
		return fmt.Errorf("couldn't init keycloak permission client: %v", err)
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
	return sshtoken.Serve(ctx, log, l, p, ldb, keycloakToken, keycloakPermission,
		hostkeys)
}
