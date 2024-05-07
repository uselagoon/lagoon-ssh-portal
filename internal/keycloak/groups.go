package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"

	"golang.org/x/oauth2/clientcredentials"
)

// Group represents a Keycloak Group. It holds the fields required when getting
// a list of groups from keycloak.
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) httpClient(ctx context.Context) *http.Client {
	cc := clientcredentials.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		TokenURL:     c.oidcConfig.TokenEndpoint,
	}
	return cc.Client(ctx)
}

// rawGroups returns the raw JSON group representation from the Keycloak API.
func (c *Client) rawGroups(ctx context.Context) ([]byte, error) {
	groupsURL := *c.baseURL
	groupsURL.Path = path.Join(c.baseURL.Path,
		"/auth/admin/realms/lagoon/groups")
	req, err := http.NewRequestWithContext(ctx, "GET", groupsURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct groups request: %v", err)
	}
	q := req.URL.Query()
	q.Add("briefRepresentation", "true")
	req.URL.RawQuery = q.Encode()
	res, err := c.httpClient(ctx).Do(req)
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

// GroupNameGroupIDMap returns a map of Keycloak Group names to Group IDs.
func (c *Client) GroupNameGroupIDMap(
	ctx context.Context,
) (map[string]string, error) {
	data, err := c.rawGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("couldn't get groups from Keycloak API: %v", err)
	}
	var groups []Group
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal Keycloak groups: %v", err)
	}
	groupNameGroupIDMap := map[string]string{}
	for _, group := range groups {
		groupNameGroupIDMap[group.Name] = group.ID
	}
	return groupNameGroupIDMap, nil
}
