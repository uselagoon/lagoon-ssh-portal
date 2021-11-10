package permission

import (
	"fmt"

	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
)

// map environment type to role which can SSH
var envTypeRoleCanSSH = map[lagoon.EnvironmentType][]lagoon.UserRole{
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
func UserCanSSHToEnvironment(env *lagoondb.Environment, realmRoles,
	userGroups []string, groupProjectIDs map[string][]int) bool {
	// check for platform owner
	for _, r := range realmRoles {
		if r == "platform-owner" {
			return true
		}
	}
	validRoles := envTypeRoleCanSSH[env.Type]
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
