/*
*
  - Authorization request & access token request: authorize.go
  - Pushed Authorization request: par.go
  - userinfo request: userinfo.go
  - introspect request: introspect.go
  - refresh_token request: refresh_token.go

*
*/
package oidcclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	client_http "github.com/vdbulcke/oidc-client-demo/src/client/http"
	"github.com/vdbulcke/oidc-client-demo/src/client/internal/oidc/discovery"
	"github.com/vdbulcke/oidc-client-demo/src/client/jwt/signer"
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

	// oidc well-known
	Wellknown *discovery.OIDCWellKnownOpenidConfiguration

	// jwt signer
	jwtsigner signer.JwtSigner
}

// subCtxKey key to store 'sub' in context
type subCtxKey string

// OIDCClient create a new OIDC Client
func NewOIDCClient(c *OIDCClientConfig, jwtsigner signer.JwtSigner, clientCert tls.Certificate, l hclog.Logger) (*OIDCClient, error) {

	if c.AuthMethod == "private_key_jwt" && jwtsigner == nil {
		return nil, errors.New(" '--pem-key' is required for 'private_key_jwt' auth method")
	}

	ctx := context.Background()

	if c.SkipTLSVerification {
		l.Warn("TLS Validation is disabled")
	}

	clientCerts := []tls.Certificate{}
	// set client cert for mTLS
	if c.AuthMethod == "tls_client_auth" {
		clientCerts = append(clientCerts, clientCert)
	}

	// http client set custom transport
	httpClient := client_http.NewHttpClient(c.HttpClientConfig, l, clientCerts)
	http.DefaultClient = httpClient

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
			return nil, errors.New("wellknown validation error")
		}
	}

	// if Well Known Requires PAR
	if wk.RequirePushedAuthorizationRequests {
		l.Warn("Pushed Authorization Request is required")
		c.UsePAR = true
	}

	// if no explicit 'par_endpoint'
	if c.UsePAR && c.PAREndpoint == "" {

		// try to get it from standard Well Known endpoint property
		if wk.PushedAuthorizationRequestEndpoint != "" {
			c.PAREndpoint = wk.PushedAuthorizationRequestEndpoint

		} else if c.PARIntrospectEndpointWellKnownKey != "" {
			// if alternative key on well known is defined
			par := wk.WellKnownRaw[c.PARIntrospectEndpointWellKnownKey]
			if par == nil {
				l.Error("could not find PAR endpoint on well-known", "key", c.PARIntrospectEndpointWellKnownKey)

			} else {
				//nolint
				switch par := par.(type) {
				case string:
					c.PAREndpoint = par
				}

			}
		}

		if c.PAREndpoint == "" {
			l.Error("no PAR endpoint defined with 'use_par: true'")
			return nil, errors.New("invalid config")
		}

	}
	// override setting from well-known endpoint
	if c.AuthorizeEndpoint != "" {
		wk.AuthorizationEndpoint = c.AuthorizeEndpoint
	}
	if c.TokenEndpoint != "" {
		wk.TokenEndpoint = c.TokenEndpoint
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

	// setting auth method
	switch c.AuthMethod {
	case "client_secret_basic":
		oAuthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInHeader

	case "client_secret_post":
		oAuthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		oAuthConfig.Endpoint.AuthStyle = oauth2.AuthStyleAutoDetect

	}

	return &OIDCClient{
		config:      c,
		logger:      l,
		ctx:         ctx,
		verifier:    verifier,
		oAuthConfig: oAuthConfig,
		provider:    provider,
		jwkVerifier: jwkVerifier,
		Wellknown:   wk,
		jwtsigner:   jwtsigner,
	}, nil
}
