package keycloak

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// LagoonClaims contains the token claims used by Lagoon.
type LagoonClaims struct {
	RealmRoles      []string `json:"realm_roles"`
	UserGroups      []string `json:"group_membership"`
	AuthorizedParty string   `json:"azp"`
	jwt.RegisteredClaims

	clientID string `json:"-"`
}

// Validate performs the Lagoon-specific JWT validation checks.
//
// In practice, it checks the AuthorizedParty to confirm the token is for us.
// Keycloak adds this field to access tokens for token-exchange operations.
// This field is described in the ID token spec:
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// If this check fails something is very broken :'(
//
// This function relies on the clientID field being filled correctly during
// LagoonClaims construction.
func (l LagoonClaims) Validate() error {
	if l.clientID != l.AuthorizedParty {
		return fmt.Errorf("invalid azp, expected %s got %s",
			l.clientID, l.AuthorizedParty)
	}
	return nil
}

// parseAccessToken takes an OAuth2 token and validates its signature and
// other fields. It returns the access token's LagoonClaims if valid, and an
// error otherwise.
func (c *Client) parseAccessToken(t *oauth2.Token,
	sub string, opts ...jwt.ParserOption) (*LagoonClaims, error) {
	opts = append(opts,
		jwt.WithSubject(sub),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	tok, err := jwt.ParseWithClaims(
		t.AccessToken,
		&LagoonClaims{clientID: c.clientID},
		c.jwks.Keyfunc,
		opts...)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse user token: %v", err)
	}
	claims, ok := tok.Claims.(*LagoonClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims type: %T", tok.Claims)
	}
	if !tok.Valid {
		// this should never happen because invalid tokens will return an error
		// from jwt.ParseWithClaims()
		return nil, fmt.Errorf("invalid token with no error")
	}
	return claims, nil
}
