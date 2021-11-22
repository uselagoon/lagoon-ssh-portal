package keycloak

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUnmarshalUserAttributes(t *testing.T) {
	var testCases = map[string]struct {
		input  []byte
		expect *userAttributes
	}{
		"two groups": {
			input: []byte(`{
		"group_lagoon_project_ids": [
			"{\"credentialtest-group1\":[1]}",
   		"{\"ci-group\":[3,4,5,6,7,8,9,10,11,12,17,14,16,20,21,24,19,23,31]}"]}`),
			expect: &userAttributes{
				regularAttributes: regularAttributes{
					RealmRoles: nil,
					UserGroups: nil,
				},
				GroupProjectIDs: map[string][]int{
					"credentialtest-group1": {1},
					"ci-group": {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 14, 16, 20, 21, 24,
						19, 23, 31},
				},
			},
		},
		"multiple attributes": {
			input: []byte(`{
				"jti":"ba279e79-4f38-43ae-83e7-fe461aad59d1",
				"exp":1637296288,
				"nbf":0,
				"iat":1637295988,
				"iss":"http://lagoon-core-keycloak:8080/auth/realms/lagoon",
				"aud":"account",
				"sub":"91435afe-ba81-406b-9308-f80b79fae350",
				"typ":"Bearer",
				"azp":"service-api",
				"auth_time":0,
				"session_state":"14ffd91a-86e3-4ce3-93b7-2df3591fcdaf",
				"acr":"1",
				"realm_access":
				 {"roles":
				 	["owner",
				 	 "platform-owner",
				 	 "offline_access",
				 	 "guest",
				 	 "reporter",
				 	 "developer",
				 	 "uma_authorization",
				 	 "maintainer"]},
				"resource_access":
				 {"account":
				 	{"roles":["manage-account", "manage-account-links", "view-profile"]}},
				"scope":"profile email",
				"group_membership":
				 ["/ci-group/ci-group-owner",
				  "/credentialtest-group1/credentialtest-group1-owner"],
				"realm_roles":
				 ["owner",
				  "platform-owner",
				  "offline_access",
				  "guest",
				  "reporter",
				  "developer",
				  "uma_authorization",
				  "maintainer"],
				"email_verified":true,
				"group_lagoon_project_ids":
 				 ["{\"credentialtest-group1\":[1]}",
					"{\"ci-group\":[3,4,5,6,7,8,9,10,11,12,17,14,16,20,21,24,19,23,31]}"]
				}`),
			expect: &userAttributes{
				regularAttributes: regularAttributes{
					RealmRoles: []string{
						"owner",
						"platform-owner",
						"offline_access",
						"guest",
						"reporter",
						"developer",
						"uma_authorization",
						"maintainer"},
					UserGroups: []string{
						"/ci-group/ci-group-owner",
						"/credentialtest-group1/credentialtest-group1-owner"},
				},
				GroupProjectIDs: map[string][]int{
					"credentialtest-group1": {1},
					"ci-group": {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 14, 16, 20, 21, 24,
						19, 23, 31},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			var ua *userAttributes
			err := json.Unmarshal(tc.input, &ua)
			if err != nil {
				tt.Fatal(err)
			}
			if !reflect.DeepEqual(ua, tc.expect) {
				tt.Fatalf("got: %v, expected %v", ua, tc.expect)
			}
		})
	}
}
