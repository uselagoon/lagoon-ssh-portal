package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
)

// UserRolesAndGroups queries Keycloak given the user UUID, and returns the
// user's realm roles, group memberships, and the project IDs associated with
// those groups.
func (c *Client) UserRolesAndGroups(ctx context.Context,
	userUUID *uuid.UUID) ([]string, []string, map[string][]int, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "UserRolesAndGroups")
	defer span.End()
	// get user token
	tokenURL := *c.baseURL
	tokenURL.Path = path.Join(tokenURL.Path,
		`/auth/realms/lagoon/protocol/openid-connect/token`)
	userConfig := oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenURL.String(),
		},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Timeout: 10 * time.Second,
	})
	userToken, err := userConfig.Exchange(ctx, "",
		// https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
		oauth2.SetAuthURLParam("grant_type",
			"urn:ietf:params:oauth:grant-type:token-exchange"),
		// https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange
		oauth2.SetAuthURLParam("requested_subject", userUUID.String()),
		oauth2.SetAuthURLParam("audience", c.clientID))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't get user token: %v", err)
	}
	fmt.Println("user access token:")
	fmt.Println(userToken.AccessToken)
	// parse and extract verified attributes
	claims, err := c.validateTokenClaims(userToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't validate token claims: %v", err)
	}
	return claims.RealmRoles, claims.UserGroups, claims.GroupProjectIDs, nil
}
