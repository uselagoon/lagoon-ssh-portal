package keycloak

import "golang.org/x/oauth2"

// ValidateTokenClaims is a helper method to expose the underlying private
// method for unit testing.
func (c *Client) ValidateTokenClaims(t *oauth2.Token) (*LagoonClaims, error) {
	return c.validateTokenClaims(t)
}
