// Package rbac contains permission logic for Lagoon.
package rbac

import (
	"context"

	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
)

// Default permission map of environment type to roles which can SSH.
//
// By default:
// - Developer and higher can SSH to development environments.
// - Maintainer and higher can SSH to production environments.
//
// See https://docs.lagoon.sh/administering-lagoon/rbac/#group-roles for more
// information.
//
// Note that this does not affect the platform-owner role, which can always SSH
// to any environment.
var defaultEnvTypeRoleCanSSH = map[lagoon.EnvironmentType]map[lagoon.UserRole]bool{
	lagoon.Development: {
		lagoon.Developer:  true,
		lagoon.Maintainer: true,
		lagoon.Owner:      true,
	},
	lagoon.Production: {
		lagoon.Maintainer: true,
		lagoon.Owner:      true,
	},
}

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	AncestorGroups(context.Context, []uuid.UUID) ([]uuid.UUID, error)
	UserGroupIDRole(context.Context, []string) map[uuid.UUID]lagoon.UserRole
	UserRolesAndGroups(context.Context, uuid.UUID) ([]string, []string, error)
}

// LagoonDBService provides methods for querying the Lagoon API DB.
type LagoonDBService interface {
	ProjectGroupIDs(context.Context, int) ([]uuid.UUID, error)
}

// Permission encapsulates the permission logic for Lagoon.
// This object should not be constructed by itself, only via NewPermission().
type Permission struct {
	keycloak          KeycloakService
	lagoonDB          LagoonDBService
	envTypeRoleCanSSH map[lagoon.EnvironmentType]map[lagoon.UserRole]bool
}

// Option performs optional configuration on Permission objects during
// initialization, and is passed to NewPermission().
type Option func(*Permission)

// BlockDeveloperSSH configures the Permission object returned by
// NewPermission() to disallow Developer SSH access to Lagoon environments.
// Instead, only Maintainers and Owners can SSH to either Development or
// Production environments.
func BlockDeveloperSSH() Option {
	return func(p *Permission) {
		p.envTypeRoleCanSSH = map[lagoon.EnvironmentType]map[lagoon.UserRole]bool{
			lagoon.Development: {
				lagoon.Maintainer: true,
				lagoon.Owner:      true,
			},
			lagoon.Production: {
				lagoon.Maintainer: true,
				lagoon.Owner:      true,
			},
		}
	}
}

// NewPermission applies the given Options and returns a new Permission object.
func NewPermission(
	k KeycloakService,
	l LagoonDBService,
	opts ...Option,
) *Permission {
	p := Permission{
		keycloak:          k,
		lagoonDB:          l,
		envTypeRoleCanSSH: defaultEnvTypeRoleCanSSH,
	}
	for _, opt := range opts {
		opt(&p)
	}
	return &p
}
