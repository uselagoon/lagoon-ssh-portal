package keycloak_test

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
)

// newTestUGIDRoleServer sets up a mock keycloak which responds with
// appropriate group JSON data to exercise UserGroupIDRole.
func newTestUGIDRoleServer(tt *testing.T) *httptest.Server {
	// set up the map of group requests to responses
	var reqRespMap = map[string]string{
		"ee6d02d1-b14b-41dd-95b6-cb8c26b1a321/children": "testdata/usergroups_children0.json",
		"7f22ce84-c0af-4ff4-afcd-288f0473deb5/children": "testdata/usergroups_children1.json",
		"2e833d9b-39b7-4f25-b37f-cfb8765015ab/children": "testdata/usergroups_children2.json",
		"139ad442-1d20-4c58-b009-c0afe21bf85b/children": "testdata/usergroups_children3.json",
		"54486df8-450d-4b62-8e10-223ac3419d05/children": "testdata/usergroups_children4.json",
		"eca344cd-2b81-4447-bcf9-ce07aa9d4a1b/children": "testdata/usergroups_children5.json",
		"52c2e558-d939-4d76-b241-910386d59aa7/children": "testdata/usergroups_children6.json",
		"c7d3b738-91f2-4cf1-aeec-2ab444eb3215/children": "testdata/usergroups_children7.json",
		"879d1d38-97d8-449a-affd-8529b8e31feb/children": "testdata/usergroups_children8.json",
	}
	// load the discovery JSON first, because the mux closure needs to
	// reference its buffer
	discoveryBuf, err := os.ReadFile("testdata/realm.oidc.discovery.json")
	if err != nil {
		tt.Fatal(err)
		return nil
	}
	// configure router with the URLs that OIDC discovery and JWKS require
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/realms/lagoon/.well-known/openid-configuration",
		func(w http.ResponseWriter, r *http.Request) {
			d := bytes.NewBuffer(discoveryBuf)
			_, err = io.Copy(w, d)
			if err != nil {
				tt.Fatal(err)
			}
		})
	mux.HandleFunc("/auth/realms/lagoon/protocol/openid-connect/certs",
		func(w http.ResponseWriter, r *http.Request) {
			f, err := os.Open("testdata/realm.oidc.certs.json")
			if err != nil {
				tt.Fatal(err)
				return
			}
			_, err = io.Copy(w, f)
			if err != nil {
				tt.Fatal(err)
			}
		})
	// configure the group paths
	for groupID, file := range reqRespMap {
		mux.HandleFunc("/auth/admin/realms/lagoon/groups/"+groupID,
			func(w http.ResponseWriter, r *http.Request) {
				responseData, err := os.Open(file)
				if err != nil {
					tt.Fatal(err)
					return
				}
				_, err = io.Copy(w, responseData)
				if err != nil {
					tt.Fatal(err)
				}
			})
	}
	// configure the "all groups" paths
	mux.HandleFunc("/auth/admin/realms/lagoon/groups",
		func(w http.ResponseWriter, r *http.Request) {
			paramFirst := r.URL.Query().Get("first")
			paramMax := r.URL.Query().Get("max")
			assert.Equal(tt, "5", paramMax)
			dataPath :=
				fmt.Sprintf("testdata/usergroups_groups_first%s.json", paramFirst)
			f, err := os.Open(dataPath)
			if err != nil {
				tt.Fatal(err)
				return
			}
			_, err = io.Copy(w, f)
			if err != nil {
				tt.Fatal(err)
			}
		})
	ts := httptest.NewServer(mux)
	// now replace the example URL in the discovery JSON with the actual
	// httptest server URL
	discoveryBuf = bytes.ReplaceAll(discoveryBuf,
		[]byte("https://keycloak.example.com"), []byte(ts.URL))
	return ts
}

func TestUserGroupIDRole(t *testing.T) {
	var testCases = map[string]struct {
		userGroupPaths []string
		expect         map[uuid.UUID]lagoon.UserRole
	}{
		"single project owner": {
			userGroupPaths: []string{
				"/project-a-fishy-website/project-a-fishy-website-owner",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("54486df8-450d-4b62-8e10-223ac3419d05"): lagoon.Owner,
			},
		},
		"multi project member": {
			userGroupPaths: []string{
				"/project-a-fishy-website/project-a-fishy-website-owner",
				"/project-a-website-for-cats/project-a-website-for-cats-maintainer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("54486df8-450d-4b62-8e10-223ac3419d05"): lagoon.Owner,
				uuid.MustParse("52c2e558-d939-4d76-b241-910386d59aa7"): lagoon.Maintainer,
			},
		},
		"regular group maintainer": {
			userGroupPaths: []string{
				"/corp6-senior-devs/corp6-senior-devs-maintainer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("eca344cd-2b81-4447-bcf9-ce07aa9d4a1b"): lagoon.Maintainer,
			},
		},
		"child subgroup developer": {
			userGroupPaths: []string{
				"/scott-test-ancestor-group2/scott-test-child-group2/scott-test-child-group2-developer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"): lagoon.Developer,
			},
		},
		"grandchild subgroup owner": {
			userGroupPaths: []string{
				"/scott-test-ancestor-group2/scott-test-child-group3/scott-test-grandchild-group3/scott-test-grandchild-group3-owner",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("139ad442-1d20-4c58-b009-c0afe21bf85b"): lagoon.Owner,
			},
		},
		"multiple grandchild subgroups exercise cache": {
			userGroupPaths: []string{
				"/scott-test-ancestor-group2/scott-test-child-group2/scott-test-grandchild-group2/scott-test-grandchild-group2-maintainer",
				"/scott-test-ancestor-group2/scott-test-child-group2/scott-test-grandchild-group2b/scott-test-grandchild-group2b-owner",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("879d1d38-97d8-449a-affd-8529b8e31feb"): lagoon.Maintainer,
				uuid.MustParse("c7d3b738-91f2-4cf1-aeec-2ab444eb3215"): lagoon.Owner,
			},
		},
		"project, regular, and subgroups": {
			userGroupPaths: []string{
				"/project-a-fishy-website/project-a-fishy-website-owner",
				"/corp6-senior-devs/corp6-senior-devs-maintainer",
				"/scott-test-ancestor-group2/scott-test-child-group2/scott-test-child-group2-developer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("54486df8-450d-4b62-8e10-223ac3419d05"): lagoon.Owner,
				uuid.MustParse("eca344cd-2b81-4447-bcf9-ce07aa9d4a1b"): lagoon.Maintainer,
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"): lagoon.Developer,
			},
		},
		"multiple roles in the same group highest first": {
			userGroupPaths: []string{
				"/corp6-senior-devs/corp6-senior-devs-maintainer",
				"/corp6-senior-devs/corp6-senior-devs-developer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("eca344cd-2b81-4447-bcf9-ce07aa9d4a1b"): lagoon.Maintainer,
			},
		},
		"multiple roles in the same group lowest first": {
			userGroupPaths: []string{
				"/corp6-senior-devs/corp6-senior-devs-developer",
				"/corp6-senior-devs/corp6-senior-devs-maintainer",
			},
			expect: map[uuid.UUID]lagoon.UserRole{
				uuid.MustParse("eca344cd-2b81-4447-bcf9-ce07aa9d4a1b"): lagoon.Maintainer,
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ts := newTestUGIDRoleServer(tt)
			defer ts.Close()
			// init keycloak client
			k, err := keycloak.NewClient(
				tt.Context(),
				slog.New(slog.NewJSONHandler(os.Stderr, nil)),
				ts.URL,
				"auth-server",
				"",
				10,
				400,
				false)
			if err != nil {
				tt.Fatal(err)
			}
			// override internal HTTP client for testing
			k.UseDefaultHTTPClient()
			// override default huge pages
			k.UsePageSize(5)
			// perform testing
			gidRoleMap := k.UserGroupIDRole(tt.Context(), tc.userGroupPaths)
			assert.Equal(tt, tc.expect, gidRoleMap, name)
		})
	}
}
