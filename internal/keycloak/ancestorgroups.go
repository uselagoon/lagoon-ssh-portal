package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// rawGroup returns the raw JSON group representation of a single keycloak
// group.
func (c *Client) rawGroup(
	ctx context.Context,
	groupID uuid.UUID,
) ([]byte, error) {
	// set up tracing
	timer := prometheus.NewTimer(
		keycloakRequestLatencyVec.WithLabelValues("rawGroup"))
	defer timer.ObserveDuration()
	// perform query
	groupURL := *c.baseURL
	groupURL.Path = path.Join(
		c.baseURL.Path,
		"/auth/admin/realms/lagoon/groups",
		groupID.String())
	req, err := http.NewRequestWithContext(ctx, "GET", groupURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct group request: %v", err)
	}
	q := req.URL.Query()
	q.Add("briefRepresentation", "false")
	req.URL.RawQuery = q.Encode()
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`couldn't get groupID "%s": %v`, groupID.String(), err)
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("bad group response: %d\n%s", res.StatusCode, body)
	}
	return io.ReadAll(res.Body)
}

// groupByID takes a group (UU)ID and returns the group object it identifies.
func (c *Client) groupByID(
	ctx context.Context,
	groupID uuid.UUID,
) (*Group, error) {
	// prefer to use cached value
	group, ok := c.groupIDGroupCache.Get(groupID)
	if ok {
		return &group, nil
	}
	// otherwise get data from keycloak
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("couldn't wait for limiter: %v", err)
	}
	data, err := c.rawGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("couldn't get group from Keycloak API: %v", err)
	}
	if err := json.Unmarshal(data, &group); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal group: %v", err)
	}
	if group.ID == nil {
		return nil, fmt.Errorf("group with nil ID: %v", group)
	}
	// update cache
	c.groupIDGroupCache.Set(*group.ID, group)
	return &group, nil
}

// ancestorGroupIDs takes a group (UU)ID and returns a slice of all ancestor
// group IDs.
func (c *Client) ancestorGroupIDs(
	ctx context.Context,
	groupID uuid.UUID,
) ([]uuid.UUID, error) {
	var ancestorGIDs []uuid.UUID
	group, err := c.groupByID(ctx, groupID)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't get group %s by ID: %v", groupID.String(), err)
	}
	if group.ParentID != nil {
		// this is not a top level group
		// get the ancestors of the parent
		grandParentGIDs, err := c.ancestorGroupIDs(ctx, *group.ParentID)
		if err != nil {
			return nil,
				fmt.Errorf("couldn't get ancestors of %s: %v", group.ParentID.String(), err)
		}
		ancestorGIDs = append(ancestorGIDs, *group.ParentID)
		ancestorGIDs = append(ancestorGIDs, grandParentGIDs...)
	}
	return ancestorGIDs, nil
}

// AncestorGroups takes a slice of group IDs, and returns the same slice
// with any ancestor group IDs appended.
func (c *Client) AncestorGroups(
	ctx context.Context,
	groupIDs []uuid.UUID,
) ([]uuid.UUID, error) {
	var allGIDs []uuid.UUID
	allGIDs = append(allGIDs, groupIDs...)
	for _, gid := range groupIDs {
		ancestorGIDs, err := c.ancestorGroupIDs(ctx, gid)
		if err != nil {
			return nil,
				fmt.Errorf(`couldn't get ancestor group IDs for "%v": %v`, gid, err)
		}
		allGIDs = append(allGIDs, ancestorGIDs...)
	}
	// remove duplicates from allGIDs
	slices.SortFunc(allGIDs, uuid.Compare)
	return slices.Compact(allGIDs), nil
}
