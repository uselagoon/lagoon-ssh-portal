package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"go.opentelemetry.io/otel"
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/rbac"

// calculateUserCanSSHToEnvironment takes a slice of project Group IDs
// (the direct project group as well as any ancestor groups), a map of user
// group IDs to Lagoon user roles, and a map of user roles to access
// permissions.
// This function returns true if the user is a member of any of the given
// project groups, with a role that permits SSH access, and false otherwise.
func calculateUserCanSSHToEnvironment(
	projectGroupIDs []uuid.UUID,
	userGroupIDRole map[uuid.UUID]lagoon.UserRole,
	sshRoles map[lagoon.UserRole]bool,
) bool {
	for _, pgid := range projectGroupIDs {
		userRole, ok := userGroupIDRole[pgid]
		if !ok {
			continue
		}
		if sshRoles[userRole] {
			return true
		}
	}
	return false
}

// UserCanSSHToEnvironment returns true if the given environment can be
// connected to via SSH by the user with the given realm roles and user groups,
// and false otherwise.
func (p *Permission) UserCanSSHToEnvironment(
	ctx context.Context,
	log *slog.Logger,
	userUUID uuid.UUID,
	projectID int,
	envType lagoon.EnvironmentType,
) (bool, error) {
	// set up tracing
	_, span := otel.Tracer(pkgName).Start(ctx, "UserCanSSHToEnvironment")
	defer span.End()
	// get the user roles and group paths
	realmRoles, userGroupPaths, err := p.keycloak.UserRolesAndGroups(ctx, userUUID)
	if err != nil {
		return false,
			fmt.Errorf("couldn't query roles and groups for user %v: %v", userUUID, err)
	}
	// check for platform owner
	if slices.Contains(realmRoles, "platform-owner") {
		log.Debug("granting permission due to platform-owner realm role",
			slog.Any("realmRoles", realmRoles))
		return true, nil
	}
	// convert the group paths to group ID -> role map
	userGroupIDRole := p.keycloak.UserGroupIDRole(ctx, userGroupPaths)
	// get the IDs of all groups the project is in
	projectGroupIDs, err := p.lagoonDB.ProjectGroupIDs(ctx, projectID)
	if err != nil {
		return false,
			fmt.Errorf("couldn't get group IDs for project %v: %v", projectID, err)
	}
	// expand the group IDs for the project with any ancestor groups, since the
	// user's membership of all ancestor groups should be considered when
	// calculating permissions.
	ancestorGroups, err := p.keycloak.AncestorGroups(ctx, projectGroupIDs)
	if err != nil {
		return false,
			fmt.Errorf("couldn't expand project group IDs %v: %v", projectID, err)
	}
	sshRoles := p.envTypeRoleCanSSH[envType]
	log.Debug("assessing permission",
		slog.Any("realmRoles", realmRoles),
		slog.Any("userGroupIDRole", userGroupIDRole),
		slog.Any("projectGroupIDs", projectGroupIDs),
		slog.Any("sshRoles", sshRoles),
		slog.String("userID", userUUID.String()),
	)
	return calculateUserCanSSHToEnvironment(
		ancestorGroups, userGroupIDRole, sshRoles), nil
}
