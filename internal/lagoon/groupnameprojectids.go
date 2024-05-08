// Package lagoon provides Lagoon-specific functionality which doesn't fit
// cleanly into the other service packages such as Keycloak or Lagoon DB.
package lagoon

import (
	"context"
	"fmt"
	"strings"
)

// DBService provides methods for querying the Lagoon API DB.
type DBService interface {
	GroupIDProjectIDsMap(context.Context) (map[string][]int, error)
}

// KeycloakService provides methods for querying the Keycloak API.
type KeycloakService interface {
	GroupNameGroupIDMap(context.Context) (map[string]string, error)
}

// given a nested user group name like "/foo-bar/foo-bar-owner", sanity check
// the format and return the top-level group name (between the separators).
func groupNameFromUserGroup(userGroup string) (string, error) {
	parts := strings.Split(userGroup, `/`)
	switch {
	case len(parts) != 3:
		return "", fmt.Errorf(`unknown user group format: %v`, userGroup)
	case len(parts[0]) != 0:
		return "", fmt.Errorf(`missing leading "/": %v`, userGroup)
	case len(parts[1]) == 0:
		return "", fmt.Errorf(`missing group name: %v`, userGroup)
	case len(parts[2]) == 0:
		return "", fmt.Errorf(`missing subgroup name: %v`, userGroup)
	default:
		return parts[1], nil
	}
}

// GroupNameProjectIDsMap generates a map of group names to project IDs for the
// groups the user is a member of. userGroups should be a slice of groups
// including subgroups in the format returned from
func GroupNameProjectIDsMap(
	ctx context.Context,
	ldb DBService,
	k KeycloakService,
	userGroups []string,
) (map[string][]int, error) {
	// get the map of group names to group IDs
	groupNameGroupIDMap, err := k.GroupNameGroupIDMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't query keycloak groups: %v", err)
	}
	// get the group -> project memberships
	groupIDProjectIDsMap, err := ldb.GroupIDProjectIDsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't query Lagoon DB group projects: %v", err)
	}
	groupNameProjectIDsMap := map[string][]int{}
	for _, userGroup := range userGroups {
		// carve out group name from the user group
		groupName, err := groupNameFromUserGroup(userGroup)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse user group: %v", err)
		}
		// for each user group, get the group ID
		groupID, ok := groupNameGroupIDMap[groupName]
		if !ok {
			return nil, fmt.Errorf("couldn't get group ID for group: %v", groupName)
		}
		// use the group ID to find the group projects and map groupName to project
		// IDs in the groupProjectIDs map
		groupNameProjectIDsMap[groupName] = groupIDProjectIDsMap[groupID]
	}
	return groupNameProjectIDsMap, nil
}
