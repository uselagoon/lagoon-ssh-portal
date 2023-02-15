// Package rbac contains permission logic for Lagoon.
package rbac

import "github.com/uselagoon/ssh-portal/internal/lagoon"

// Permission encapsulates the permission logic for Lagoon.
// This object should not be constructed by itself, only via NewPermission().
type Permission struct {
	envTypeRoleCanSSH map[lagoon.EnvironmentType][]lagoon.UserRole
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
		p.envTypeRoleCanSSH = map[lagoon.EnvironmentType][]lagoon.UserRole{
			lagoon.Development: {
				lagoon.Maintainer,
				lagoon.Owner,
			},
			lagoon.Production: {
				lagoon.Maintainer,
				lagoon.Owner,
			},
		}
	}
}

// NewPermission applies the given Options and returns a new Permission object.
func NewPermission(opts ...Option) *Permission {
	p := Permission{
		envTypeRoleCanSSH: defaultEnvTypeRoleCanSSH,
	}
	for _, opt := range opts {
		opt(&p)
	}
	return &p
}
