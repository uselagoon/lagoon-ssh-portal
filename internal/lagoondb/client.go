// Package lagoondb provides an interface to the Lagoon API database.
package lagoondb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
// Namespace name.
func (c *Client) EnvironmentByNamespaceName(
	ctx context.Context,
	name string,
) (*Environment, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "EnvironmentByNamespaceName")
	defer span.End()
	// run query
	env := Environment{}
	err := c.db.GetContext(ctx, &env,
		`SELECT environment.environment_type AS type, `+
			`environment.id AS id, `+
			`environment.name AS name, `+
			`environment.openshift_project_name AS namespace_name, `+
			`project.id AS project_id, `+
			`project.name AS project_name `+
			`FROM environment JOIN project ON environment.project = project.id `+
			`WHERE environment.openshift_project_name = ? `+
			`AND environment.deleted = '0000-00-00 00:00:00' `+
			`LIMIT 1`, name)
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
	err := c.db.GetContext(ctx, &user,
		`SELECT user_ssh_key.usid AS uuid `+
			`FROM user_ssh_key JOIN ssh_key ON user_ssh_key.skid = ssh_key.id `+
			`WHERE ssh_key.key_fingerprint = ?`,
		fingerprint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResult
		}
		return nil, err
	}
	// usid column in set NOT NULL, so this should be impossible
	if user.UUID == nil {
		return nil, errors.New("NULL user UUID")
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
	err := c.db.GetContext(ctx, &ssh,
		`SELECT openshift.ssh_host AS ssh_host, `+
			`openshift.ssh_port AS ssh_port `+
			`FROM environment JOIN openshift ON environment.openshift = openshift.id `+
			`WHERE environment.id = ?`,
		envID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNoResult
		}
		return "", "", err
	}
	return ssh.Host, ssh.Port, nil
}

// SSHKeyUsed sets the last_used attribute of the ssh key identified by the
// given fingerprint to used.
//
// The value of used is converted to UTC before being stored in a DATETIME
// column in the MySQL database.
func (c *Client) SSHKeyUsed(
	ctx context.Context,
	fingerprint string,
	used time.Time,
) error {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "SSHKeyUsed")
	defer span.End()
	// run query
	_, err := c.db.ExecContext(ctx,
		`UPDATE ssh_key `+
			`SET last_used = ? `+
			`WHERE key_fingerprint = ?`,
		used.UTC().Format(time.DateTime),
		fingerprint)
	if err != nil {
		return fmt.Errorf("couldn't update last_used for key_fingerprint=%s: %v",
			fingerprint, err)
	}
	return nil
}

// ProjectGroupIDs returns a slice of Group (UU)IDs of which the project
// identified by the given projectID is a member.
func (c *Client) ProjectGroupIDs(
	ctx context.Context,
	projectID int,
) ([]uuid.UUID, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "ProjectGroupIDs")
	defer span.End()
	// run query
	var gids []uuid.UUID
	err := c.db.SelectContext(ctx, &gids,
		`SELECT group_id `+
			`FROM kc_group_projects `+
			`WHERE project_id = ?`,
		projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResult
		}
		return nil, err
	}
	return gids, nil
}
