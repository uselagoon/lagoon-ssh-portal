package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
)

func (c *Client) getUserToken(ctx context.Context,
	userUUID *uuid.UUID) (*oauth2.Token, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "getUserToken")
	defer span.End()
	// get user token
	userConfig := oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: c.oidcConfig.TokenEndpoint,
		},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Timeout: 8 * time.Second,
	})
	userToken, err := userConfig.Exchange(ctx, "",
		// https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
		oauth2.SetAuthURLParam("grant_type",
			"urn:ietf:params:oauth:grant-type:token-exchange"),
		// https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange
		oauth2.SetAuthURLParam("requested_subject", userUUID.String()))
	if err != nil {
		return nil, fmt.Errorf("couldn't get user token: %v", err)
	}
	// parse and extract verified attributes
	_, err = c.parseAccessToken(userToken, userUUID.String())
	if err != nil {
		return nil, fmt.Errorf("couldn't parse user access token: %v", err)
	}
	return userToken, nil
}

// UserAccessTokenResponse queries Keycloak given the user UUID, and returns an
// access token response containing both access_token and refresh_token.
// Authorized party for these tokens is auth-server. Authorization is done by
// the Lagoon API.
func (c *Client) UserAccessTokenResponse(ctx context.Context,
	userUUID *uuid.UUID) (string, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "UserAccessToken")
	defer span.End()
	// get user token
	userToken, err := c.getUserToken(ctx, userUUID)
	if err != nil {
		return "", fmt.Errorf("couldn't get user token: %v", err)
	}
	data, err := json.Marshal(userToken)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal user token: %v", err)
	}
	return string(data), nil
}

// UserAccessToken queries Keycloak given the user UUID, and returns an access
// token. Authorized party for this token is auth-server. Authorization is done
// by the Lagoon API.
func (c *Client) UserAccessToken(ctx context.Context,
	userUUID *uuid.UUID) (string, error) {
	// set up tracing
	ctx, span := otel.Tracer(pkgName).Start(ctx, "UserAccessToken")
	defer span.End()
	// get user token
	userToken, err := c.getUserToken(ctx, userUUID)
	if err != nil {
		return "", fmt.Errorf("couldn't get user token: %v", err)
	}
	return userToken.AccessToken, nil
}
