package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/google/uuid"
)

// defaultPageSize is the default size of the page requested when scrolling
// through group results from Keycloak.
const defaultPageSize = 1000

// Group represents a Keycloak Group. It holds the fields required when getting
// a list of groups from keycloak.
type Group struct {
	ID         *uuid.UUID          `json:"id"`
	ParentID   *uuid.UUID          `json:"parentId"`
	Name       string              `json:"name"`
	Attributes map[string][]string `json:"attributes"`
	RealmRoles []string            `json:"realmRoles"`
}

// rawGroups returns the raw JSON group representation of all top-level groups.
func (c *Client) rawGroups(ctx context.Context, first int) ([]byte, error) {
	groupsURL := *c.baseURL
	groupsURL.Path = path.Join(c.baseURL.Path,
		"/auth/admin/realms/lagoon/groups")
	req, err := http.NewRequestWithContext(ctx, "GET", groupsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct groups request: %v", err)
	}
	q := req.URL.Query()
	q.Add("briefRepresentation", "true")
	q.Add("first", strconv.Itoa(first))
	q.Add("max", strconv.Itoa(c.pageSize))
	req.URL.RawQuery = q.Encode()
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't get groups: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("bad groups response: %d\n%s", res.StatusCode, body)
	}
	return io.ReadAll(res.Body)
}

// TopLevelGroupNameGroupIDMap returns a map of top-level Keycloak Group names
// to Group IDs.
func (c *Client) TopLevelGroupNameGroupIDMap(
	ctx context.Context,
) (map[string]uuid.UUID, error) {
	// prefer to use cached value
	if groupNameGroupIDMap, ok := c.topLevelGroupNameIDCache.Get(); ok {
		return groupNameGroupIDMap, nil
	}
	// otherwise get data from keycloak
	var groups []Group
	var first int
	for {
		var page []Group
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("couldn't wait for limiter: %v", err)
		}
		data, err := c.rawGroups(ctx, first)
		if err != nil {
			return nil, fmt.Errorf("couldn't get groups from Keycloak API: %v", err)
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("couldn't unmarshal Keycloak groups: %v", err)
		}
		groups = append(groups, page...)
		if len(page) < c.pageSize {
			break // reached last page
		}
		first += c.pageSize // scroll to next page
	}
	groupNameGroupIDMap := map[string]uuid.UUID{}
	for _, group := range groups {
		groupNameGroupIDMap[group.Name] = *group.ID
		// update group ID cache
		c.groupIDGroupCache.Set(*group.ID, group)
	}
	// update top level group name cache
	c.topLevelGroupNameIDCache.Set(groupNameGroupIDMap)
	return groupNameGroupIDMap, nil
}
