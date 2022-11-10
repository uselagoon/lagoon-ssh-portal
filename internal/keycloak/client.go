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

	"go.uber.org/zap"
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
