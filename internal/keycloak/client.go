// Package keycloak implements a client for keycloak which implements
// Lagoon-specific queries.
package keycloak

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	oidcClient "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/time/rate"
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/keycloak"

// Client is a keycloak client.
type Client struct {
	baseURL      *url.URL
	clientID     string
	clientSecret string
	jwks         *keyfunc.JWKS
	log          *slog.Logger
	oidcConfig   *oidc.DiscoveryConfiguration
	limiter      *rate.Limiter
}

// NewClient creates a new keycloak client for the lagoon realm.
func NewClient(ctx context.Context, log *slog.Logger, keycloakURL, clientID,
	clientSecret string, rateLimit int) (*Client, error) {
	// discover OIDC config
	baseURL, err := url.Parse(keycloakURL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse keycloak base URL %s: %v",
			keycloakURL, err)
	}
	issuerURL := *baseURL
	issuerURL.Path = path.Join(issuerURL.Path, "auth/realms/lagoon")
	oidcConfig, err := oidcClient.Discover(ctx, issuerURL.String(),
		&http.Client{Timeout: 8 * time.Second})
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
	}, nil
}
