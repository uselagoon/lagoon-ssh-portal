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

// SSHAccessQuery defines the structure of an SSH access query.
type SSHAccessQuery struct {
	SSHFingerprint string
	NamespaceName  string
}

// Client is a Lagoon API-DB client
type Client struct {
	db *sqlx.DB
}

// Environment is a Lagoon project environment.
type Environment struct {
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
// Namespace name (on Openshift this is the project name).
func (c *Client) EnvironmentByNamespaceName(ctx context.Context, name string) (*Environment, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "EnvironmentByNamespaceName")
	defer span.End()
	// run query
	env := Environment{}
	err := c.db.GetContext(ctx, &env, `
	SELECT
		environment.name AS name,
		environment.openshift_project_name AS namespace_name,
		project.id AS project_id,
		project.name AS project_name,
		environment.environment_type AS type
	FROM environment JOIN project ON environment.project = project.id
	WHERE environment.openshift_project_name = ?`, name)
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
func (c *Client) UserBySSHFingerprint(ctx context.Context, fingerprint string) (*User, error) {
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
