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
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/vdbulcke/oauthx"
	"github.com/vdbulcke/oauthx/tracing"

	"github.com/vdbulcke/assert"
	client_http "github.com/vdbulcke/oidc-client-demo/src/client/http"
)

type OIDCClient struct {

	// the config
	config *OIDCClientConfig

	// the Hashicor Logger
	logger hclog.Logger

	// shared context for this client
	ctx context.Context

	auth   oauthx.AuthMethod
	client *oauthx.OAuthClient
}

// subCtxKey key to store 'sub' in context
type subCtxKey string

// OIDCClient create a new OIDC Client
func NewOIDCClient(c *OIDCClientConfig, privateKey oauthx.OAuthPrivateKey, clientCert tls.Certificate, l hclog.Logger) (_ *OIDCClient, err error) {

	if c.SkipTLSVerification {
		l.Warn("TLS Validation is disabled")
	}

	if c.AllowNonCompliantAmr {
		oauthx.AllowNonCompliantAmr = true
	}

	clientCerts := []tls.Certificate{}
	// set client cert for mTLS
	if c.AuthMethod == "tls_client_auth" {
		clientCerts = append(clientCerts, clientCert)
	}

	// http client set custom transport
	httpClient := client_http.NewHttpClient(c.HttpClientConfig, l, clientCerts)

	limit := c.HttpClientConfig.MaxRespSizeLimitBytes
	if limit <= 0 {
		limit = oauthx.LIMIT_HTTP_RESP_BODY_MAX_SIZE_BYTES
	}

	// create a context with trace-id header
	ctx := context.Background()
	traceId := uuid.New().String()
	ctx = tracing.ContextWithTraceID(ctx, "x-trace-id", traceId)
	if c.HttpClientConfig != nil && c.HttpClientConfig.ExtraHeader != nil {
		ctx = tracing.ContextWithExtraHeader(ctx, c.HttpClientConfig.ExtraHeader)
	}
	l.Debug("Initial context", "trace_id", traceId)

	// Let's starts by getting the AS metadata configuration
	var wk *oauthx.WellKnownConfiguration

	if c.AlternativeWellKnownEndpoint != "" {
		l.Warn("Using Alternative wellknown", "url", c.AlternativeWellKnownEndpoint)

		wk, err = oauthx.NewInsecureWellKnownEndpoint(ctx, c.AlternativeWellKnownEndpoint, oauthx.WellKnownWithHttpClient(httpClient, limit))
		if err != nil {

			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				l.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}
			return nil, fmt.Errorf("insecure wellknown: %w", err)
		}

	} else if c.InsecureWellKnownEndpoint {
		wkEndpoint := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
		wk, err = oauthx.NewInsecureWellKnownEndpoint(ctx, wkEndpoint, oauthx.WellKnownWithHttpClient(httpClient, limit))
		if err != nil {
			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				l.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}
			return nil, fmt.Errorf("oidc wellknown: %w", err)
		}

	} else {

		// fetch /.well-known/openid-configuration
		wk, err = oauthx.NewWellKnownOpenidConfiguration(ctx, c.Issuer, oauthx.WellKnownWithHttpClient(httpClient, limit))
		if err != nil {
			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				l.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}
			return nil, fmt.Errorf("oidc wellknown: %w", err)
		}
	}

	// let use override endpoint from remote server
	if c.PAREndpoint != "" {
		wk.PushedAuthorizationRequestEndpoint = c.PAREndpoint
	}
	if c.AuthorizeEndpoint != "" {
		wk.AuthorizationEndpoint = c.AuthorizeEndpoint
	}
	if c.TokenEndpoint != "" {
		wk.TokenEndpoint = c.TokenEndpoint
	}
	if c.UserinfoEndpoint != "" {
		wk.UserinfoEndpoint = c.UserinfoEndpoint
	}
	if c.IntrospectEndpoint != "" {
		wk.IntrospectionEndpoint = c.IntrospectEndpoint
	}
	if c.JwksEndpoint != "" {
		wk.JwksUri = c.JwksEndpoint
	}
	if c.PAREndpoint != "" {
		wk.PushedAuthorizationRequestEndpoint = c.PAREndpoint
	}
	if c.EndSessionEndpoint != "" {
		wk.EndSessionEndpoint = c.EndSessionEndpoint
	}
	if c.RevocationEndpoint != "" {
		wk.RevocationEndpoint = c.RevocationEndpoint
	}

	if len(c.TokenSigningAlg) > 0 {
		wk.IDTokenSigningAlgValuesSupported = c.TokenSigningAlg
		wk.UserinfoSigningAlgValuesSupported = c.TokenSigningAlg
		wk.IntrospectionEndpointAuthSigningAlgValuesSupported = c.TokenSigningAlg
	}

	// parse auth method
	var auth oauthx.AuthMethod
	switch c.AuthMethod {
	case "client_secret_basic":
		assert.StrNotEmpty(c.ClientID, assert.Exit, "missing client_id")
		assert.StrNotEmpty(c.ClientSecret, assert.Exit, "missing client_secret")
		auth = oauthx.NewBasicAuth(c.ClientID, c.ClientSecret)
	case "client_secret_post":
		assert.StrNotEmpty(c.ClientID, assert.Exit, "missing client_id")
		assert.StrNotEmpty(c.ClientSecret, assert.Exit, "missing client_secret")
		auth = oauthx.NewClientSecretPost(c.ClientID, c.ClientSecret)
	case "private_key_jwt":
		assert.NotNil(privateKey, assert.Exit, " '--pem-key' is required for 'private_key_jwt' auth method")

		opts := []oauthx.PrivateKeyJwtOptFunc{}
		opts = append(opts, oauthx.WithPrivateKeyJwtTTL(c.JwtProfileTokenDuration))
		if c.ClientIDParamForTokenEndpoint {
			opts = append(opts, oauthx.WithPrivateKeyJwtAlwaysIncludeClientIdParam())
		}

		if c.JwtProfileAudiance != "" {
			opts = append(opts, oauthx.WithPrivateKeyJwtFixedAudiance(c.JwtProfileAudiance))
		}

		if c.JwtProfileEndpointAsAudiance {
			opts = append(opts, oauthx.WithPrivateKeyJwtEndpointAsAudiance())
		}
		if c.JwtProfilePARAudiance != "" {
			opts = append(opts, oauthx.WithPrivateKeyJwtAlternativeEndpointAudiance(oauthx.PushedAuthorizationRequestEndpoint, c.JwtProfilePARAudiance))
		}
		if c.JwtProfileTokenAudiance != "" {
			opts = append(opts, oauthx.WithPrivateKeyJwtAlternativeEndpointAudiance(oauthx.TokenEndpoint, c.JwtProfileTokenAudiance))
		}
		if c.JwtProfileRevocationAudiance != "" {
			opts = append(opts, oauthx.WithPrivateKeyJwtAlternativeEndpointAudiance(oauthx.RevocationEndpoint, c.JwtProfileRevocationAudiance))
		}
		if c.JwtProfileIntrospectionAudiance != "" {
			opts = append(opts, oauthx.WithPrivateKeyJwtAlternativeEndpointAudiance(oauthx.IntrospectionEndpoint, c.JwtProfileIntrospectionAudiance))
		}

		auth = oauthx.NewPrivateKeyJwt(c.ClientID, privateKey, opts...)
	case "none":

		auth = oauthx.NewAuthMethodNone(c.ClientID)

	default:
		return nil, fmt.Errorf("invalid auth method %s", c.AuthMethod)
	}

	// create OauthClient with opts

	opts := []oauthx.OAuthClientOptFunc{
		oauthx.WithAuthMethod(auth),
		oauthx.WithHttpClientWithLimit(httpClient, limit),
	}

	if privateKey != nil {
		opts = append(opts, oauthx.WithOAuthPrivateKey(privateKey))
	}

	if c.UseRequestParameter {
		assert.NotNil(privateKey, assert.Exit, "rfc9101: require '--pem-key' to generate 'request=' jwt parameter")
	}

	client := oauthx.NewOAuthClient(c.ClientID, wk, opts...)

	return &OIDCClient{
		config: c,
		client: client,
		ctx:    ctx,
		logger: l,
		auth:   auth,
	}, nil
}
