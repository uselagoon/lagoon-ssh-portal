package rbac_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/rbac"
	"go.uber.org/mock/gomock"
)

func TestUserCanSSHDefaultRBAC(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		// input
		userUUID  uuid.UUID
		projectID int
		envType   lagoon.EnvironmentType
		// mock data
		realmRoles      []string
		userGroupPaths  []string
		userGroupIDRole map[uuid.UUID]lagoon.UserRole
		projectGroupIDs []uuid.UUID
		// ancestorGroups must be a superset of projectGroupIDs
		ancestorGroups []uuid.UUID
		// this flag avoids setting up mock expectations when realm role attributes
		// mean RBAC logic is short-circuited
		realmRoleShortCircuit bool
		// expectations
		permissionDefault         bool
		permissionBlockDevelopers bool
	}{
		"maintainer wrong project dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupPaths: []string{
				"/project-foo/project-foo-maintainer",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			},
			permissionDefault:         false,
			permissionBlockDevelopers: false,
		},
		"owner wrong project prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupPaths: []string{
				"/customer-a/customer-a-maintainer",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Owner,
				uuid.MustParse("00000000-0000-0000-0000-000000000002"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			permissionDefault:         false,
			permissionBlockDevelopers: false,
		},
		"maintainer ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupPaths: []string{
				"/project-bar/project-bar-maintainer",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"maintainer ssh to dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupPaths: []string{
				"/customer-b/customer-b-maintainer",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Maintainer,
				uuid.MustParse("00000000-0000-0000-0000-000000000002"): lagoon.Maintainer,
				uuid.MustParse("00000000-0000-0000-0000-000000000003"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"parent group maintainer ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000002"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"grandparent group maintainer ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"): lagoon.Maintainer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"grandparent group developer ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"): lagoon.Developer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			permissionDefault:         false,
			permissionBlockDevelopers: false,
		},
		"grandparent group developer ssh to dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000003"): lagoon.Developer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: false,
		},
		"platform-owner ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
				"platform-owner",
			},
			realmRoleShortCircuit:     true,
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"developer ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Developer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         false,
			permissionBlockDevelopers: false,
		},
		"developer ssh to dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Developer,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: false,
		},
		"owner ssh to prod": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Production,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Owner,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"owner ssh to dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Owner,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         true,
			permissionBlockDevelopers: true,
		},
		"guest ssh to dev": {
			userUUID:  uuid.UUID{},
			projectID: 4,
			envType:   lagoon.Development,
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroupIDRole: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"): lagoon.Guest,
			},
			projectGroupIDs: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			ancestorGroups: []uuid.UUID{
				uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			},
			permissionDefault:         false,
			permissionBlockDevelopers: false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctx := context.Background()
			// set up mocks
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			kcService := NewMockKeycloakService(ctrl)
			kcService.EXPECT().
				UserRolesAndGroups(ctx, tc.userUUID).
				Return(tc.realmRoles, tc.userGroupPaths, nil).
				Times(2)
			ldbService := NewMockLagoonDBService(ctrl)
			if !tc.realmRoleShortCircuit {
				kcService.EXPECT().
					UserGroupIDRole(ctx, tc.userGroupPaths).
					Return(tc.userGroupIDRole).
					Times(2)
				ldbService.EXPECT().
					ProjectGroupIDs(ctx, tc.projectID).
					Return(tc.projectGroupIDs, nil).
					Times(2)
				kcService.EXPECT().
					AncestorGroups(ctx, tc.projectGroupIDs).
					Return(tc.ancestorGroups, nil).
					Times(2)
			}
			// test default permission engine
			permDefault := rbac.NewPermission(kcService, ldbService)
			ok, err := permDefault.UserCanSSHToEnvironment(
				ctx,
				log,
				tc.userUUID,
				tc.projectID,
				tc.envType,
			)
			if err != nil {
				tt.Fatalf("couldn't perform user SSH permisison check: %v", err)
			}
			if ok != tc.permissionDefault {
				tt.Fatalf("expected %v, got %v", tc.permissionDefault, ok)
			}
			// test alternative permission engine which blocks developer SSH access
			permBlockDev := rbac.NewPermission(
				kcService,
				ldbService,
				rbac.BlockDeveloperSSH(),
			)
			ok, err = permBlockDev.UserCanSSHToEnvironment(
				ctx,
				log,
				tc.userUUID,
				tc.projectID,
				tc.envType,
			)
			if err != nil {
				tt.Fatalf("couldn't perform user SSH permisison check: %v", err)
			}
			if ok != tc.permissionBlockDevelopers {
				tt.Fatalf("expected %v, got %v", tc.permissionDefault, ok)
			}
		})
	}
}
