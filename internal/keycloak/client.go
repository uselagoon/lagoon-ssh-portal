// Package keycloak implements a client for keycloak which implements
// Lagoon-specific queries.
package keycloak

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/keycloak"

// Client is a keycloak client.
type Client struct {
	baseURL      *url.URL
	clientID     string
	clientSecret string
	jwtPubKey    *rsa.PublicKey
	log          *zap.Logger
}

// NewClient creates a new keycloak client.
func NewClient(ctx context.Context, log *zap.Logger, baseURL, clientID,
	clientSecret string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse base URL %s: %v", baseURL, err)
	}
	pubKey, err := publicKey(ctx, *u)
	if err != nil {
		return nil, fmt.Errorf("couldn't get realm public key: %v", err)
	}
	return &Client{
		baseURL:      u,
		clientID:     clientID,
		clientSecret: clientSecret,
		jwtPubKey:    pubKey,
		log:          log,
	}, nil
}

// publicKey queries the keycloak lagoon realm metadata endpoint and returns
// the RSA public key used to sign JWTs
func publicKey(ctx context.Context, u url.URL) (*rsa.PublicKey, error) {
	// get the metadata JSON
	client := &http.Client{Timeout: 10 * time.Second}
	u.Path = path.Join(u.Path, `/auth/realms/lagoon`)
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't get realm metadata: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode > 299 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("bad realm metadata response: %d\n%s",
			res.StatusCode, body)
	}
	// extract public key
	jd := json.NewDecoder(res.Body)
	metadata := struct {
		PubKey string `json:"public_key"`
	}{}
	if err = jd.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("couldn't decode public key from metadata: %v", nil)
	}
	if len(metadata.PubKey) == 0 {
		return nil, fmt.Errorf("couldn't extract public key from metadata")
	}
	// decode and parse RSA public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(metadata.PubKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode public key value: %v", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse PKIX pub key: %v", err)
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type: %T", pubKey)
	}
	return rsaPubKey, nil
}

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
		oauth2.SetAuthURLParam("requested_subject", userUUID.String()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't get user token: %v", err)
	}
	c.log.Debug("got user token")
	// parse and extract verified attributes
	tok, err := jwt.ParseWithClaims(userToken.AccessToken, &SSHAPIClaims{},
		func(_ *jwt.Token) (any, error) { return c.jwtPubKey, nil })
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't parse user account token: %v", err)
	}
	if tok.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		return nil, nil, nil,
			fmt.Errorf("unexepcted token signing algorithm: expected %s, got %s",
				jwt.SigningMethodRS256.Alg(), tok.Method.Alg())
	}
	claims, ok := tok.Claims.(*SSHAPIClaims)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid token claims type: %T", tok.Claims)
	}
	// Sanity check the AuthorizedParty to confirm the token is for us.
	// Keycloak adds this field for token-exchange operations.
	// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	if claims.AuthorizedParty != "service-api" {
		return nil, nil, nil, fmt.Errorf("invalid azp, expected service-api got %s",
			claims.AuthorizedParty)
	}
	return claims.RealmRoles, claims.UserGroups, claims.GroupProjectIDs, nil
}
