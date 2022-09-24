package oidcclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	"github.com/vdbulcke/oidc-client-demo/oidc-client/internal/oidc/discovery"
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

	// JWT Verifier
	jwkVerifier *oidc.IDTokenVerifier

	// OAauth2 Config
	oAuthConfig oauth2.Config
}

// subCtxKey key to store 'sub' in context
type subCtxKey string

// OIDCClient create a new OIDC Client
func NewOIDCClient(c *OIDCClientConfig, l hclog.Logger) (*OIDCClient, error) {

	ctx := context.Background()

	if c.SkipTLSVerification {
		l.Warn("TLS Validation is disabled")
	}

	// skipping the TLS verification endpoint could be self signed
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: c.SkipTLSVerification,
	}

	// construct well-known from Issuer, and discover well known
	wellKnown := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"

	if c.AlternativeWellKnownEndpoint != "" {
		// override wellknown if an alternative is provided
		wellKnown = c.AlternativeWellKnownEndpoint
		l.Warn("Using Alternative wellknown", "url", c.AlternativeWellKnownEndpoint)
	}

	wk, err := discovery.NewWellKnown(wellKnown)
	if err != nil {
		l.Error("Could not get WellKnown endpoint", "err", err)
		return nil, err
	}

	if !c.InsecureWellKnownEndpoint {
		if !discovery.ValidWellKnown(wk, c.Issuer, l) {
			return nil, errors.New("Wellknown validation error")
		}
	}

	// Create a oidc Provider Config manually
	providerConfig := &oidc.ProviderConfig{
		IssuerURL:   c.Issuer,
		AuthURL:     wk.AuthorizationEndpoint,
		TokenURL:    wk.TokenEndpoint,
		UserInfoURL: wk.UserinfoEndpoint,
		JWKSURL:     wk.JwksUri,
		Algorithms:  wk.IDTokenSigningAlgValuesSupported,
	}

	provider := providerConfig.NewProvider(ctx)
	if err != nil {
		l.Error("Could create OIDC provider form WellKnown endpoint", "err", err)
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
		// SupportedSigningAlgs: []string{c.config.TokenSigningAlg},
		SupportedSigningAlgs: c.TokenSigningAlg,
	}

	jwtConfig := &oidc.Config{
		ClientID:             c.ClientID,
		SupportedSigningAlgs: c.TokenSigningAlg,
		SkipClientIDCheck:    true,  // Disable check Audience == clientID
		SkipIssuerCheck:      false, // Check Issuer
	}

	var verifier, jwkVerifier *oidc.IDTokenVerifier

	if c.JwksEndpoint != "" {

		keySet := oidc.NewRemoteKeySet(ctx, c.JwksEndpoint)
		verifier = oidc.NewVerifier(c.Issuer, keySet, oidcConfig)
		jwkVerifier = oidc.NewVerifier(c.Issuer, keySet, jwtConfig)

		if l.IsDebug() {
			l.Debug("Using Custom JWK endpoint", "jwk_endpoint", c.JwksEndpoint)
		}

	} else {
		verifier = provider.Verifier(oidcConfig)
		jwkVerifier = provider.Verifier(jwtConfig)
	}

	// new OAuth2 Config
	oAuthConfig := oauth2.Config{
		ClientID:    c.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: c.RedirectUri,
		Scopes:      c.Scopes,
	}

	// only set client secret if defined
	if c.ClientSecret != "" {
		oAuthConfig.ClientSecret = c.ClientSecret
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
		jwkVerifier: jwkVerifier,
	}, nil
}
