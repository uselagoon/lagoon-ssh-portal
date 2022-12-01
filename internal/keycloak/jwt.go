package keycloak

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
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
}

// validateTokenClaims takes an OAuth2 token and validates its signature and
// claims. It returns the validated claims if valid, or an error otherwise.
func (c *Client) validateTokenClaims(t *oauth2.Token) (*LagoonClaims, error) {
	// parse and extract verified attributes
	tok, err := jwt.ParseWithClaims(t.AccessToken, &LagoonClaims{},
		func(_ *jwt.Token) (any, error) { return c.jwtPubKey, nil })
	if err != nil {
		c.log.Debug("token parsing error", zap.Error(err),
			zap.String("accessToken", t.AccessToken))
		return nil, fmt.Errorf("couldn't parse user access token: %v", err)
	}
	if tok.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		return nil, fmt.Errorf("unexepcted signing algorithm: expected %s, got %s",
			jwt.SigningMethodRS256.Alg(), tok.Method.Alg())
	}
	claims, ok := tok.Claims.(*LagoonClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims type: %T", tok.Claims)
	}
	// Sanity check the AuthorizedParty to confirm the token is for us.
	// Keycloak adds this field for token-exchange operations.
	// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	// If this check fails something is very broken :'(
	if claims.AuthorizedParty != c.clientID {
		return nil, fmt.Errorf("invalid azp, expected %s got %s",
			c.clientID, claims.AuthorizedParty)
	}
	return claims, nil
}
