package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Client is a keycloak client.
type Client struct {
	ctx          context.Context
	baseURL      *url.URL
	clientID     string
	clientSecret string
	jwtSecret    string
	log          *zap.Logger
}

// realmAccess is a helper struct for json unmarshalling
type realmAccess struct {
	Roles []string `json:"roles"`
}

// attributes injected into the access token by keycloak
type userAttributes struct {
	RealmAccess     *realmAccess     `json:"realm_access"`
	UserGroups      []string         `json:"groups"`
	GroupProjectIDs map[string][]int `json:"group_lagoon_project_ids"`
}

// NewClient creates a new keycloak client.
func NewClient(ctx context.Context, log *zap.Logger, baseURL, clientID,
	clientSecret, jwtSecret string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		ctx:          ctx,
		baseURL:      u,
		clientID:     clientID,
		clientSecret: clientSecret,
		jwtSecret:    jwtSecret,
		log:          log,
	}, nil
}

// UserRolesAndGroups queries Keycloak given the user UUID, and returns the
// user's realm roles, group memberships, and the project IDs associated with
// those groups.
func (c *Client) UserRolesAndGroups(userUUID *uuid.UUID) ([]string, []string,
	map[string][]int, error) {
	// get user token
	tokenURL := c.baseURL
	tokenURL.Path = path.Join(tokenURL.Path,
		`/auth/realms/lagoon/protocol/openid-connect/token`)
	userConfig := oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenURL.String(),
		},
	}
	ctx := context.WithValue(c.ctx, oauth2.HTTPClient, &http.Client{
		Timeout: 10 * time.Second,
	})
	userToken, err := userConfig.Exchange(ctx, "",
		// https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
		oauth2.SetAuthURLParam("grant_type",
			"urn:ietf:params:oauth:grant-type:token-exchange"),
		// https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange
		oauth2.SetAuthURLParam("requested_subject", userUUID.String()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't get user token: %v", err)
	}
	c.log.Debug("got user token", zap.String("access token",
		userToken.AccessToken))
	// parse and extract verified attributes
	tok, err := jwt.ParseSigned(userToken.AccessToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't parse verified access token: %v", err)
	}
	var attr userAttributes
	if err = tok.Claims(c.jwtSecret, &attr); err != nil {
		return nil, nil, nil,
			fmt.Errorf("couldn't extract token claims: %v", err)
	}
	return attr.RealmAccess.Roles, attr.UserGroups, attr.GroupProjectIDs, nil
}
