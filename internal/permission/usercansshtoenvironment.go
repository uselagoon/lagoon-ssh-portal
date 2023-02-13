package permission

import (
	"context"
	"fmt"

	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"go.opentelemetry.io/otel"
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/permission"

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
var defaultEnvTypeRoleCanSSH = map[lagoon.EnvironmentType][]lagoon.UserRole{
	lagoon.Development: {
		lagoon.Developer,
		lagoon.Maintainer,
		lagoon.Owner,
	},
	lagoon.Production: {
		lagoon.Maintainer,
		lagoon.Owner,
	},
}

// UserCanSSHToEnvironment returns true if the given environment can be
// connected to via SSH by the user with the given realm roles and user groups,
// and false otherwise.
func (p *Permission) UserCanSSHToEnvironment(ctx context.Context, env *lagoondb.Environment,
	realmRoles, userGroups []string, groupProjectIDs map[string][]int) bool {
	// set up tracing
	_, span := otel.Tracer(pkgName).Start(ctx, "UserCanSSHToEnvironment")
	defer span.End()
	// check for platform owner
	for _, r := range realmRoles {
		if r == "platform-owner" {
			return true
		}
	}
	validRoles := p.envTypeRoleCanSSH[env.Type]
	// check if the user is directly a member of the project group and has the
	// required role
	var validProjectGroups []string
	for _, role := range validRoles {
		validProjectGroups = append(validProjectGroups,
			fmt.Sprintf("/project-%s/project-%s-%s",
				env.ProjectName, env.ProjectName, role))
	}
	for _, userGroup := range userGroups {
		for _, validProjectGroup := range validProjectGroups {
			if userGroup == validProjectGroup {
				return true
			}
		}
	}
	// check if the user is a member of a group containing the project and has
	// the required role
	for group, pids := range groupProjectIDs {
		for _, pid := range pids {
			if pid == env.ProjectID {
				// user is in the same group as project, check if they have the
				// required role
				var validGroups []string
				for _, role := range validRoles {
					validGroups = append(validGroups,
						fmt.Sprintf("/%s/%s-%s", group, group, role))
				}
				for _, userGroup := range userGroups {
					for _, validGroup := range validGroups {
						if userGroup == validGroup {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
