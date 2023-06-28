package keycloak

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type groupProjectIDs map[string][]int

func (gpids *groupProjectIDs) UnmarshalJSON(data []byte) error {
	// unmarshal the double-encoded group-pid attributes
	var gpas []string
	if err := json.Unmarshal(data, &gpas); err != nil {
		return err
	}
	// convert the slice of encoded group-pid attributes into a slice of
	// group-pid maps
	var gpms []map[string][]int
	for _, gpa := range gpas {
		var gpm map[string][]int
		if err := json.Unmarshal([]byte(gpa), &gpm); err != nil {
			return err
		}
		gpms = append(gpms, gpm)
	}
	// flatten the slice of group-pid maps into a single map
	*gpids = groupProjectIDs{}
	for _, gpm := range gpms {
		for k, v := range gpm {
			(*gpids)[k] = v
		}
	}
	return nil
}

// LagoonClaims contains the token claims used by Lagoon.
type LagoonClaims struct {
	RealmRoles      []string        `json:"realm_roles"`
	UserGroups      []string        `json:"group_membership"`
	GroupProjectIDs groupProjectIDs `json:"group_lagoon_project_ids"`
	AuthorizedParty string          `json:"azp"`
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
