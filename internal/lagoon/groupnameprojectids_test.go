package lagoon_test

import (
	"context"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/mock"
	"go.uber.org/mock/gomock"
)

var (
	groupNameGroupIDMap = map[string]string{
		"project-bs-demo":                    "89c2894b-5345-453d-839d-2c210fe9b18d",
		"project-drupal-example":             "948adf3d-f075-4659-925d-7d1d4a85f0ba",
		"project-skip-test-project":          "ea6bd1a8-a1e7-46cc-a62e-cca8dc27f5ed",
		"project-test-drupal-example-simple": "0ce10b5d-72ca-40a5-a33f-056b8565521f",
		"another-random-group":               "7fd49076-5fc9-4b2f-9998-3a3eff731ec0",
	}
	groupIDProjectIDsMap = map[string][]int{
		"89c2894b-5345-453d-839d-2c210fe9b18d": {1, 23},
		"948adf3d-f075-4659-925d-7d1d4a85f0ba": {45},
		"ea6bd1a8-a1e7-46cc-a62e-cca8dc27f5ed": {6, 7, 8},
		"0ce10b5d-72ca-40a5-a33f-056b8565521f": {90},
		"7fd49076-5fc9-4b2f-9998-3a3eff731ec0": {2, 3},
	}
)

func TestGroupNameProjectIDsMap(t *testing.T) {
	var testCases = map[string]struct {
		input       []string
		expect      map[string][]int
		expectError bool
	}{
		"happy path": {
			input: []string{
				"/project-bs-demo/project-as-demo-developer",
				"/project-drupal-example/project-drupal-example-maintainer",
				"/project-skip-test-project/project-skip-test-project-owner",
				"/project-test-drupal-example-simple/project-test-drupal-example-simple-maintainer",
			},
			expect: map[string][]int{
				"project-bs-demo":                    {1, 23},
				"project-drupal-example":             {45},
				"project-skip-test-project":          {6, 7, 8},
				"project-test-drupal-example-simple": {90},
			},
		},
		"invalid group name": {
			input: []string{
				"/project-bs-demo/project-as-demo-developer",
				"/project-drupal-example/project-drupal-example-maintainer",
				"/project-skip-test-project/project-skip-test-project-owner",
				"invalid-group/foo",
			},
			expectError: true,
		},
		"unknown group": {
			input: []string{
				"/project-vandelay/project-as-demo-developer",
				"/project-drupal-example/project-drupal-example-maintainer",
				"/project-skip-test-project/project-skip-test-project-owner",
				"/project-test-drupal-example-simple/project-test-drupal-example-simple-maintainer",
			},
			expectError: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctx := context.Background()
			// set up mocks
			ctrl := gomock.NewController(tt)
			kcService := mock.NewMockKeycloakService(ctrl)
			dbService := mock.NewMockDBService(ctrl)
			// configure mocks
			kcService.EXPECT().GroupNameGroupIDMap(ctx).Return(groupNameGroupIDMap, nil)
			dbService.EXPECT().GroupIDProjectIDsMap(ctx).Return(groupIDProjectIDsMap, nil)
			// test function
			gnpids, err := lagoon.GroupNameProjectIDsMap(ctx, dbService, kcService, tc.input)
			if tc.expectError {
				assert.Error(tt, err, name)
			} else {
				assert.NoError(tt, err, name)
				assert.Equal(tt, tc.expect, gnpids, name)
			}
		})
	}
}
