// Package lagoondb provides an interface to the Lagoon API database.
package lagoondb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"go.opentelemetry.io/otel"
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/lagoondb"

// Client is a Lagoon API-DB client
type Client struct {
	db *sqlx.DB
}

// Environment is a Lagoon project environment.
type Environment struct {
	ID            int                    `db:"id"`
	Name          string                 `db:"name"`
	NamespaceName string                 `db:"namespace_name"`
	ProjectID     int                    `db:"project_id"`
	ProjectName   string                 `db:"project_name"`
	Type          lagoon.EnvironmentType `db:"type"`
}

// User is a Lagoon user.
type User struct {
	UUID *uuid.UUID `db:"uuid"`
}

// groupProjectMapping maps Lagoon group ID to project ID.
// This type is only used for database unmarshalling.
type groupProjectMapping struct {
	GroupID   string `db:"group_id"`
	ProjectID int    `db:"project_id"`
}

// ErrNoResult is returned by client methods if there is no result.
var ErrNoResult = errors.New("no rows in result set")

// NewClient returns a new Lagoon DB Client.
func NewClient(ctx context.Context, dsn string) (*Client, error) {
	db, err := sqlx.ConnectContext(ctx, "mysql", dsn)
	if err != nil {
		return nil, err
	}
	// https://github.com/go-sql-driver/mysql#important-settings
	db.SetConnMaxLifetime(4 * time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	return &Client{
		db: db,
	}, nil
}

// EnvironmentByNamespaceName returns the Environment associated with the given
// Namespace name (on Openshift this is the project name).
func (c *Client) EnvironmentByNamespaceName(
	ctx context.Context,
	name string,
) (*Environment, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "EnvironmentByNamespaceName")
	defer span.End()
	// run query
	env := Environment{}
	err := c.db.GetContext(ctx, &env, `
	SELECT
		environment.environment_type AS type,
		environment.id AS id,
		environment.name AS name,
		environment.openshift_project_name AS namespace_name,
		project.id AS project_id,
		project.name AS project_name
	FROM environment JOIN project ON environment.project = project.id
	WHERE environment.openshift_project_name = ?
	AND environment.deleted = '0000-00-00 00:00:00'
	LIMIT 1`, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResult
		}
		return nil, err
	}
	return &env, nil
}

// UserBySSHFingerprint returns the User associated with the given
// SSH fingerprint.
func (c *Client) UserBySSHFingerprint(
	ctx context.Context,
	fingerprint string,
) (*User, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "UserBySSHFingerprint")
	defer span.End()
	// run query
	user := User{}
	err := c.db.GetContext(ctx, &user, `
	SELECT user_ssh_key.usid AS uuid
	FROM user_ssh_key JOIN ssh_key ON user_ssh_key.skid = ssh_key.id
	WHERE ssh_key.key_fingerprint = ?`, fingerprint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResult
		}
		return nil, err
	}
	return &user, nil
}

// SSHEndpointByEnvironmentID returns the SSH host and port of the ssh-portal
// associated with the given environment ID.
func (c *Client) SSHEndpointByEnvironmentID(ctx context.Context,
	envID int) (string, string, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "SSHEndpointByEnvironmentID")
	defer span.End()
	// run query
	ssh := struct {
		Host string `db:"ssh_host"`
		Port string `db:"ssh_port"`
	}{}
	err := c.db.GetContext(ctx, &ssh, `
	SELECT
		openshift.ssh_host AS ssh_host,
		openshift.ssh_port AS ssh_port
	FROM environment JOIN openshift ON environment.openshift = openshift.id
	WHERE environment.id = ?`, envID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNoResult
		}
		return "", "", err
	}
	return ssh.Host, ssh.Port, nil
}

// GroupIDProjectIDsMap returns a map of Group (UU)IDs to Project IDs.
// This denotes Project Group membership in Lagoon.
func (c *Client) GroupIDProjectIDsMap(
	ctx context.Context,
) (map[string][]int, error) {
	var gpms []groupProjectMapping
	err := c.db.SelectContext(ctx, &gpms, `
	SELECT group_id, project_id
	FROM kc_group_projects`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResult
		}
		return nil, err
	}
	groupIDProjectIDsMap := map[string][]int{}
	// no need to check for duplicates here since the table has:
	// UNIQUE KEY `group_project` (`group_id`,`project_id`)
	for _, gpm := range gpms {
		groupIDProjectIDsMap[gpm.GroupID] =
			append(groupIDProjectIDsMap[gpm.GroupID], gpm.ProjectID)
	}
	return groupIDProjectIDsMap, nil
}
