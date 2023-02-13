// Package permission contains permission logic for Lagoon.
package permission

import "github.com/uselagoon/ssh-portal/internal/lagoon"

// Permission encapsulates the permission logic for Lagoon.
// This object should not be constructed by itself, only via NewPermission().
type Permission struct {
	envTypeRoleCanSSH map[lagoon.EnvironmentType][]lagoon.UserRole
}

// Option performs optional configuration on Permission objects during
// initialization, and is passed to NewPermission().
type Option func(*Permission)

// WithRBACCanSSH configures a custom RBAC ruleset governing which user roles
// (developer, maintainer etc.) can SSH into which Lagoon environment types
// (development, production).
func WithRBACCanSSH(rbacCanSSH map[lagoon.EnvironmentType][]lagoon.UserRole) Option {
	return func(p *Permission) {
		p.envTypeRoleCanSSH = rbacCanSSH
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
