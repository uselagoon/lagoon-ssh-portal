// Package keycloak implements a client for keycloak which implements
// Lagoon-specific queries.
package keycloak

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/cache"
	oidcClient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/time/rate"
)

const (
	pkgName = "github.com/uselagoon/ssh-portal/internal/keycloak"

	httpTimeout = 8 * time.Second
)

// newHTTPClient constructs an HTTP client with a reasonable timeout using
// oauth2 client credentials. This client will automatically and transparently
// refresh its OAuth2 token as requried.
func newHTTPClient(
	ctx context.Context,
	clientID,
	clientSecret,
	tokenURL string,
) *http.Client {
	cc := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	client := cc.Client(ctx)
	client.Timeout = httpTimeout
	return client
}

// Client is a keycloak client.
type Client struct {
	baseURL      *url.URL
	clientID     string
	clientSecret string
	jwks         *keyfunc.JWKS
	log          *slog.Logger
	oidcConfig   *oidc.DiscoveryConfiguration
	limiter      *rate.Limiter
	httpClient   *http.Client
	pageSize     int

	// top level groupName to groupID map cache
	topLevelGroupNameIDCache *cache.Any[map[string]uuid.UUID]
	// group ID to Group cache
	groupIDGroupCache *cache.Map[uuid.UUID, Group]
	// parent group IDs to child groups cache
	parentIDChildGroupCache *cache.Map[uuid.UUID, []Group]
}

// NewClient creates a new keycloak client for the lagoon realm.
func NewClient(
	ctx context.Context,
	log *slog.Logger,
	keycloakURL,
	clientID,
	clientSecret string,
	rateLimit int,
	insecureTLS bool,
) (*Client, error) {
	// discover OIDC config
	baseURL, err := url.Parse(keycloakURL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse keycloak base URL %s: %v",
			keycloakURL, err)
	}
	if insecureTLS {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	issuerURL := *baseURL
	issuerURL.Path = path.Join(issuerURL.Path, "auth/realms/lagoon")
	oidcConfig, err := oidcClient.Discover(ctx, issuerURL.String(),
		&http.Client{Timeout: httpTimeout})
	if err != nil {
		return nil, fmt.Errorf("couldn't discover OIDC config: %v", err)
	}
	// pull down keys via JWKS
	jwks, err := keyfunc.Get(oidcConfig.JwksURI, keyfunc.Options{})
	if err != nil {
		return nil, fmt.Errorf("couldn't get keycloak lagoon realm JWKS: %v", err)
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		jwks:         jwks,
		log:          log,
		oidcConfig:   oidcConfig,
		limiter:      rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
		httpClient:   newHTTPClient(ctx, clientID, clientSecret, oidcConfig.TokenEndpoint),
		pageSize:     defaultPageSize,

		topLevelGroupNameIDCache: cache.NewAny[map[string]uuid.UUID](),
		groupIDGroupCache:        cache.NewMap[uuid.UUID, Group](),
		parentIDChildGroupCache:  cache.NewMap[uuid.UUID, []Group](),
	}, nil
}
