package keycloak

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// ValidateTokenClaims is a helper method to expose the underlying private
// method for unit testing.
func (c *Client) ValidateToken(t *oauth2.Token, sub string,
	opts ...jwt.ParserOption) (*LagoonClaims, error) {
	return c.parseAccessToken(t, sub, opts...)
}

// SetClientID sets the Client ID for testing.
func (l *LagoonClaims) SetClientID(clientID string) {
	l.clientID = clientID
}

// UseDefaultHTTPClient uses the default http client to avoid token refresh in
// tests.
func (c *Client) UseDefaultHTTPClient() {
	c.httpClient = http.DefaultClient
}
