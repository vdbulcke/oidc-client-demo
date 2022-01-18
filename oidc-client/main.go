package oidcclient

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
)

type OIDCClient struct {

	// the config
	config *OIDCClientConfig

	// the Hashicor Logger
	logger hclog.Logger

	// shared context for this client
	ctx context.Context

	// OIDC provider
	provider *oidc.Provider

	// OIDC verifier
	verifier *oidc.IDTokenVerifier

	// OAauth2 Config
	oAuthConfig oauth2.Config
}

// OIDCClient create a new OIDC Client
func NewOIDCClient(c *OIDCClientConfig, l hclog.Logger) (*OIDCClient, error) {

	ctx := context.Background()

	// skipping the TLS verification endpoint could be self signed
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: c.SkipTLSVerification,
	}

	// provider := c.newProvider(ctx)
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		l.Error("Could create OIDC provider form WellKnown endpoint", "err", err)
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
		// SupportedSigningAlgs: []string{c.config.TokenSigningAlg},
		SupportedSigningAlgs: c.TokenSigningAlg,
	}

	verifier := provider.Verifier(oidcConfig)

	// new OAuth2 Config
	oAuthConfig := oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectUri,
		Scopes:       c.Scopes,
	}

	// override setting from well-known endpoint
	if c.AuthorizeEndpoint != "" {
		oAuthConfig.Endpoint.AuthURL = c.AuthorizeEndpoint
	}
	if c.TokenEndpoint != "" {
		oAuthConfig.Endpoint.TokenURL = c.TokenEndpoint
	}

	// setting auth method
	switch c.AuthMethod {
	case "client_secret_basic":
		oAuthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInHeader

	case "client_secret_post":
		oAuthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	}

	provider.Endpoint()
	return &OIDCClient{
		config:      c,
		logger:      l,
		ctx:         ctx,
		verifier:    verifier,
		oAuthConfig: oAuthConfig,
		provider:    provider,
	}, nil
}
