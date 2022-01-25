package permission_test

import (
	"context"
	"testing"

	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/permission"
)

type args struct {
	env             *lagoondb.Environment
	realmRoles      []string
	userGroups      []string
	groupProjectIDs map[string][]int
}

func TestUserCanSSH(t *testing.T) {
	var testCases = map[string]struct {
		input  *args
		expect bool
	}{
		"wrong project": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/project-foo/project-foo-maintainer",
			},
			groupProjectIDs: map[string][]int{
				"project-foo": {3},
			},
		}, expect: false},
		"right project": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/project-bar/project-bar-maintainer",
			},
			groupProjectIDs: map[string][]int{
				"project-bar": {4},
			},
		}, expect: true},
		"not group member": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/customer-a/customer-a-maintainer",
			},
			groupProjectIDs: map[string][]int{
				"customer-b": {4},
			},
		}, expect: false},
		"group member": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/customer-b/customer-b-maintainer",
			},
			groupProjectIDs: map[string][]int{
				"customer-b": {4},
			},
		}, expect: true},
		"platform-owner": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
				"platform-owner",
			},
			userGroups: []string{
				"/lagoonadmin",
			},
		}, expect: true},
		"developer can't ssh to prod": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/customer-b/customer-b-developer",
			},
			groupProjectIDs: map[string][]int{
				"customer-b": {4},
			},
		}, expect: false},
		"developer can ssh to dev": {input: &args{
			env: &lagoondb.Environment{
				Name:          "pr-123",
				NamespaceName: "project-bar-pr-123",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Development,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/customer-b/customer-b-developer",
			},
			groupProjectIDs: map[string][]int{
				"customer-b": {4},
			},
		}, expect: true},
		"owner can ssh to prod": {input: &args{
			env: &lagoondb.Environment{
				Name:          "production",
				NamespaceName: "project-bar-production",
				ProjectID:     4,
				ProjectName:   "project-bar",
				Type:          lagoon.Production,
			},
			realmRoles: []string{
				"offline_access",
				"uma_authorization",
			},
			userGroups: []string{
				"/customer-b/customer-b-owner",
			},
			groupProjectIDs: map[string][]int{
				"customer-b": {4},
			},
		}, expect: true},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			response := permission.UserCanSSHToEnvironment(context.Background(),
				tc.input.env, tc.input.realmRoles, tc.input.userGroups,
				tc.input.groupProjectIDs)
			if response != tc.expect {
				tt.Fatalf("expected %v, got %v", tc.expect, response)
			}
		})
	}
}
