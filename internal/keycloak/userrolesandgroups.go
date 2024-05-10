package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
)

// UserRolesAndGroups queries Keycloak given the user UUID, and returns the
// user's realm roles, and group memberships (by name, including subgroups).
func (c *Client) UserRolesAndGroups(ctx context.Context,
	userUUID *uuid.UUID) ([]string, []string, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "UserRolesAndGroups")
	defer span.End()
	// rate limit keycloak API access
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, nil, fmt.Errorf("couldn't wait for limiter: %v", err)
	}
	// get user token
	userConfig := oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: c.oidcConfig.TokenEndpoint,
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
		oauth2.SetAuthURLParam("requested_subject", userUUID.String()))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't get user token: %v", err)
	}
	// parse and extract verified attributes
	claims, err := c.parseAccessToken(userToken, userUUID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't parse user access token: %v", err)
	}
	return claims.RealmRoles, claims.UserGroups, nil
}
