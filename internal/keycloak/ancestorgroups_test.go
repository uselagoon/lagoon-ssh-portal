package keycloak_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
)

// newTestAncestorGroupsServer sets up a mock keycloak which responds with
// appropriate group JSON data to exercise AncestorGroups.
func newTestAncestorGroupsServer(tt *testing.T) *httptest.Server {
	// set up the map of group IDs to responses
	var reqRespMap map[string]string = map[string]string{
		// tree 0
		"078faf64-aa58-45cf-afb1-b585583feacf": "testdata/ancestorgroup_grandchild0.json",
		"d2d90824-c807-4162-99cf-200e38affbe2": "testdata/ancestorgroup_child0.json",
		"3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9": "testdata/ancestorgroup_parent0.json",
		// tree 1
		"879d1d38-97d8-449a-affd-8529b8e31feb": "testdata/ancestorgroup_grandchild1.json",
		"2e833d9b-39b7-4f25-b37f-cfb8765015ab": "testdata/ancestorgroup_child1.json",
		"ee6d02d1-b14b-41dd-95b6-cb8c26b1a321": "testdata/ancestorgroup_parent1.json",
		// tree 1 branch
		"7f22ce84-c0af-4ff4-afcd-288f0473deb5": "testdata/ancestorgroup_child2.json",
		"c7d3b738-91f2-4cf1-aeec-2ab444eb3215": "testdata/ancestorgroup_grandchild2.json",
		"139ad442-1d20-4c58-b009-c0afe21bf85b": "testdata/ancestorgroup_grandchild3.json",
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
	ts := httptest.NewServer(mux)
	// now replace the example URL in the discovery JSON with the actual
	// httptest server URL
	discoveryBuf = bytes.ReplaceAll(discoveryBuf,
		[]byte("https://keycloak.example.com"), []byte(ts.URL))
	return ts
}

func TestAncestorGroups(t *testing.T) {
	var testCases = map[string]struct {
		groupIDs         []uuid.UUID
		ancestorGroupIDs []uuid.UUID
	}{
		"single grandchild of ancestor group": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
				uuid.MustParse("3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
			},
		},
		"single child of ancestor group": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
			},
		},
		"two children of separate trees": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
				uuid.MustParse("3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
				uuid.MustParse("ee6d02d1-b14b-41dd-95b6-cb8c26b1a321"),
			},
		},
		"one grandchild, one child of separate trees": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
				uuid.MustParse("3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
				uuid.MustParse("ee6d02d1-b14b-41dd-95b6-cb8c26b1a321"),
			},
		},
		"one grandchild, one child of the same tree": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("078faf64-aa58-45cf-afb1-b585583feacf"),
				uuid.MustParse("3c7dea60-6dec-4f2d-b8ac-f28aa9e206d9"),
				uuid.MustParse("d2d90824-c807-4162-99cf-200e38affbe2"),
			},
		},
		"two grandchildren of the same tree": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("879d1d38-97d8-449a-affd-8529b8e31feb"),
				uuid.MustParse("c7d3b738-91f2-4cf1-aeec-2ab444eb3215"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
				uuid.MustParse("879d1d38-97d8-449a-affd-8529b8e31feb"),
				uuid.MustParse("c7d3b738-91f2-4cf1-aeec-2ab444eb3215"),
				uuid.MustParse("ee6d02d1-b14b-41dd-95b6-cb8c26b1a321"),
			},
		},
		"three grandchildren of the same tree": {
			groupIDs: []uuid.UUID{
				uuid.MustParse("879d1d38-97d8-449a-affd-8529b8e31feb"),
				uuid.MustParse("c7d3b738-91f2-4cf1-aeec-2ab444eb3215"),
				uuid.MustParse("139ad442-1d20-4c58-b009-c0afe21bf85b"),
			},
			ancestorGroupIDs: []uuid.UUID{
				uuid.MustParse("139ad442-1d20-4c58-b009-c0afe21bf85b"),
				uuid.MustParse("2e833d9b-39b7-4f25-b37f-cfb8765015ab"),
				uuid.MustParse("7f22ce84-c0af-4ff4-afcd-288f0473deb5"),
				uuid.MustParse("879d1d38-97d8-449a-affd-8529b8e31feb"),
				uuid.MustParse("c7d3b738-91f2-4cf1-aeec-2ab444eb3215"),
				uuid.MustParse("ee6d02d1-b14b-41dd-95b6-cb8c26b1a321"),
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ts := newTestAncestorGroupsServer(tt)
			defer ts.Close()
			// init keycloak client
			k, err := keycloak.NewClient(
				context.Background(),
				slog.New(slog.NewJSONHandler(os.Stderr, nil)),
				ts.URL,
				"auth-server",
				"",
				10,
				false)
			if err != nil {
				tt.Fatal(err)
			}
			// override internal HTTP client for testing
			k.UseDefaultHTTPClient()
			// perform testing
			ancestorGroupIDs, err := k.AncestorGroups(context.Background(), tc.groupIDs)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.ancestorGroupIDs, ancestorGroupIDs, name)
		})
	}
}
