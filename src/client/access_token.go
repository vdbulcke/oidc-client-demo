package oidcclient

import (
	"context"
	"net/url"

	internaloauth2 "github.com/vdbulcke/oidc-client-demo/src/client/internal/oauth2"
)

// TokenExchange call oauth2 token endpoint with the configured auth method
// expects the querystring parameters as input (token=..., grant_type=...)
func (c *OIDCClient) TokenExchange(params url.Values) (*internaloauth2.Token, error) {

	if c.config.AuthMethod == "private_key_jwt" {

		// signedJwt, err := c.GenerateJwtProfile(c.config.IntrospectEndpoint)
		signedJwt, err := c.GenerateJwtProfile(c.Wellknown.TokenEndpoint)
		if err != nil {
			c.logger.Error("Failed to generate jwt client_assertion", "err", err)
			return nil, err
		}
		c.logger.Debug("introspect setting client_assertion", "jwt", signedJwt)
		params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		params.Set("client_assertion", signedJwt)

	} else if c.config.AuthMethod == "tls_client_auth" {
		c.logger.Debug("set client_id", c.config.ClientID)
		params.Set("client_id", c.config.ClientID)
	}

	if c.config.ClientIDParamForTokenEndpoint {
		params.Set("client_id", c.config.ClientID)
	}
	c.logger.Debug("retrieve token ", "param", params)
	oauth2Token, err := internaloauth2.RetrieveToken(context.TODO(), c.config.ClientID, c.config.ClientSecret, c.Wellknown.TokenEndpoint, params, c.oAuthConfig.Endpoint.AuthStyle)
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}
