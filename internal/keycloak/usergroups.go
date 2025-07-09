package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
)

// rawChildGroups returns the raw JSON group representation of child groups of
// the given group ID.
func (c *Client) rawChildGroups(
	ctx context.Context,
	parentID uuid.UUID,
	first int,
) ([]byte, error) {
	// set up tracing
	timer := prometheus.NewTimer(
		keycloakRequestLatencyVec.WithLabelValues("rawChildGroups"))
	defer timer.ObserveDuration()
	// perform query
	groupsURL := *c.baseURL
	groupsURL.Path = path.Join(
		c.baseURL.Path,
		"/auth/admin/realms/lagoon/groups",
		parentID.String(),
		"children")
	req, err := http.NewRequestWithContext(ctx, "GET", groupsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct groups request: %v", err)
	}
	q := req.URL.Query()
	q.Add("briefRepresentation", "false")
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
		return nil, fmt.Errorf("bad child groups response for group ID %s: %d\n%s",
			parentID.String(), res.StatusCode, body)
	}
	return io.ReadAll(res.Body)
}

// topLevelGroupNameFromPath takes a slice of top level group path segments,
// such as ["", "example-company"], and performs some sanity checks to confirm
// it has the correct structure before returning the name of the top level
// group, such as "example-company".
func topLevelGroupNameFromPath(path []string) (string, error) {
	switch {
	case len(path) != 2:
		return "", fmt.Errorf(`wrong number of path segments: %v`, path)
	case len(path[0]) != 0:
		return "", fmt.Errorf(`first path segment is not empty: %v`, path)
	case len(path[1]) == 0:
		return "", fmt.Errorf(`second path segment (group name) is empty: %v`, path)
	default:
		return path[1], nil
	}
}

// topLevelGroupPathID returns the group ID for the given slice of path
// segments of a top level group path.
func (c *Client) topLevelGroupPathID(
	ctx context.Context,
	path []string,
) (*uuid.UUID, error) {
	name, err := topLevelGroupNameFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't get top level group name from path: %v", err)
	}
	groupNameIDMap, err := c.TopLevelGroupNameGroupIDMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't get group name group ID map: %v", err)
	}
	gid, ok := groupNameIDMap[name]
	if !ok {
		return nil,
			fmt.Errorf("couldn't find group name in top level groups: %v", err)
	}
	return &gid, nil
}

// groupIDFromParentAndNameCache takes a parent group ID and a child group
// name and returns the child group ID, if it exists in cache, and a boolean
// indicating if the parent group ID was found in the cache.
//
// If the parent ID exists in the cache but no cached child groups match the
// given name, the returned child group ID will be nil.
func (c *Client) groupIDFromParentAndNameCache(
	parentID uuid.UUID,
	name string,
) (*uuid.UUID, bool) {
	childGroups, ok := c.parentIDChildGroupCache.Get(parentID)
	if !ok {
		return nil, false
	}
	for _, group := range childGroups {
		if group.Name == name {
			return group.ID, true
		}
	}
	return nil, true
}

// groupIDFromParentAndName takes a parent group ID and a group name, and
// returns the group ID of the child group matching the given name.
func (c *Client) groupIDFromParentAndName(
	ctx context.Context,
	parentID uuid.UUID,
	name string,
) (*uuid.UUID, error) {
	// prefer to use cached value
	gid, ok := c.groupIDFromParentAndNameCache(parentID, name)
	if ok {
		if gid == nil {
			return nil, fmt.Errorf(`couldn't find child group "%v" in cache`, name)
		}
		return gid, nil
	}
	// otherwise get data from keycloak
	var groups []Group
	var first int
	for {
		var page []Group
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("couldn't wait for limiter: %v", err)
		}
		data, err := c.rawChildGroups(ctx, parentID, first)
		if err != nil {
			return nil, fmt.Errorf("couldn't get child groups from Keycloak: %v", err)
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("couldn't unmarshal child groups: %v", err)
		}
		groups = append(groups, page...)
		if len(page) < c.pageSize {
			break // reached last page
		}
		first += c.pageSize // scroll to next page
	}
	// update caches
	c.parentIDChildGroupCache.Set(parentID, groups)
	for _, group := range groups {
		c.groupIDGroupCache.Set(*group.ID, group)
	}
	// return group ID
	for _, group := range groups {
		if group.Name == name {
			return group.ID, nil
		}
	}
	return nil, fmt.Errorf(`couldn't find child group "%v" in keycloak`, name)
}

// groupPathID returns the ID of the group identified by path.
// path is a slice of path segments (i.e. full path split on /).
func (c *Client) groupPathID(
	ctx context.Context,
	path []string,
) (*uuid.UUID, error) {
	switch {
	case len(path) == 2:
		gid, err := c.topLevelGroupPathID(ctx, path)
		if err != nil {
			return nil,
				fmt.Errorf(`couldn't get ID for top level group path "%v": %v`,
					path[1], err)
		}
		return gid, nil
	case len(path) > 2:
		// not a top level group. find the parent ID by slicing off the last
		// segment and calling groupPathID recursively.
		parentID, err := c.groupPathID(ctx, path[:len(path)-1])
		if err != nil {
			return nil,
				fmt.Errorf(`couldn't get ID for group path "%v": %v`, path[:1], err)
		}
		groupName := path[len(path)-1]
		gid, err := c.groupIDFromParentAndName(ctx, *parentID, groupName)
		if err != nil {
			return nil,
				fmt.Errorf(`couldn't get ID for group "%s" with parent ID "%v": %v`,
					groupName, parentID, err)
		}
		return gid, nil
	default:
		return nil, fmt.Errorf(`invalid case for path "%v"`, path)
	}
}

// userGroup2Role takes a user group path, runs some validity checks to confirm
// it is a valid role subgroup, and uses it to construct a lagoon.UserRole.
func (c *Client) userGroup2Role(
	ctx context.Context,
	path []string,
) (lagoon.UserRole, error) {
	parentGroupName, userGroupName := path[len(path)-2], path[len(path)-1]
	parentNameSegments := strings.Split(parentGroupName, "-")
	nameSegments := strings.Split(userGroupName, "-")
	// validate group hierarchy
	if !slices.Equal(parentNameSegments, nameSegments[:len(nameSegments)-1]) {
		return lagoon.InvalidUserRole,
			fmt.Errorf(`invalid parent "%s" and user "%s" group structure`,
				parentGroupName, userGroupName)
	}
	// get group ID from path
	gid, err := c.groupPathID(ctx, path)
	if err != nil {
		return lagoon.InvalidUserRole,
			fmt.Errorf("couldn't get group ID from path: %v", err)
	}
	// get group from ID
	group, err := c.groupByID(ctx, *gid)
	if err != nil {
		return lagoon.InvalidUserRole,
			fmt.Errorf("couldn't get group %s by ID: %v", gid.String(), err)
	}
	// validate type attribute
	if group.Attributes == nil ||
		len(group.Attributes["type"]) != 1 ||
		group.Attributes["type"][0] != "role-subgroup" {
		return lagoon.InvalidUserRole,
			fmt.Errorf("group %s invalid type for role subgroup: %v",
				gid.String(), group.Attributes)
	}
	// validate name suffix and realmRole
	if len(group.RealmRoles) != 1 {
		return lagoon.InvalidUserRole,
			fmt.Errorf(`invalid group %s: missing realm role`, gid.String())
	}
	roleString := nameSegments[len(nameSegments)-1]
	if group.RealmRoles[0] != roleString {
		return lagoon.InvalidUserRole,
			fmt.Errorf(`invalid group %s: realmRole "%s" doesn't match name suffix "%s"`,
				gid.String(), group.RealmRoles[0], roleString)
	}
	// parse role
	role, err := lagoon.UserRoleString(roleString)
	if err != nil {
		return lagoon.InvalidUserRole,
			fmt.Errorf(`couldn't parse "%s" as user role: %v`, roleString, err)
	}
	return role, nil
}

// UserGroupIDRole takes a slice of user group paths and converts them to a
// groupID-to-role map.
func (c *Client) UserGroupIDRole(
	ctx context.Context,
	userGroupPaths []string,
) map[uuid.UUID]lagoon.UserRole {
	gidRole := map[uuid.UUID]lagoon.UserRole{}
	for _, ugp := range userGroupPaths {
		path := strings.Split(ugp, `/`)
		if len(path) < 3 {
			// Minimum segments in a valid path is three. For example,
			// "/project-foo/project-foo-maintainer" splits into
			// ["", "project-foo", "project-foo-maintainer"].
			c.log.Warn("invalid user group path",
				slog.String("userGroupPath", ugp))
			continue
		}
		role, err := c.userGroup2Role(ctx, path)
		if err != nil {
			c.log.Warn("couldn't convert user group path to role",
				slog.Any("error", err),
				slog.String("userGroup", path[len(path)-1]),
			)
			continue
		}
		// Get the group ID of the parent group.
		// Note that this parent group is what Lagoon considers to be the user's
		// group, because the lowest level containing group of the user only
		// indicates the _role_. Due to this structure, user group paths always end
		// in: $(groupName)/$(groupName)-$(role).
		gid, err := c.groupPathID(ctx, path[:len(path)-1])
		if err != nil {
			c.log.Warn("couldn't get ID of group by path",
				slog.Any("error", err),
				slog.Any("path", path[:len(path)-1]),
			)
			continue
		}
		// Handle multiple roles in the same group.
		if role > gidRole[*gid] {
			gidRole[*gid] = role
		}
	}
	return gidRole
}
