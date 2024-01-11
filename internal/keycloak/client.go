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
)

const pkgName = "github.com/uselagoon/ssh-portal/internal/keycloak"

// Client is a keycloak client.
type Client struct {
	clientID     string
	clientSecret string
	jwks         *keyfunc.JWKS
	log          *slog.Logger
	oidcConfig   *oidc.DiscoveryConfiguration
}

// NewClient creates a new keycloak client for the lagoon realm.
func NewClient(ctx context.Context, log *slog.Logger, keycloakURL, clientID,
	clientSecret string) (*Client, error) {
	// discover OIDC config
	issuerURL, err := url.Parse(keycloakURL)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse keycloak base URL %s: %v",
			keycloakURL, err)
	}
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
		clientID:     clientID,
		clientSecret: clientSecret,
		jwks:         jwks,
		log:          log,
		oidcConfig:   oidcConfig,
	}, nil
}
