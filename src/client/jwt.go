package oidcclient

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vdbulcke/oauthx"
)

type JwtProfileClaims struct {
	Jti string `json:"jti,omitempty"`
	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`
	jwt.RegisteredClaims
}

// https://www.rfc-editor.org/rfc/rfc7523.html
func (c *OIDCClient) GenerateJwtProfile(endpoint string) (string, error) {

	privateKeyJwt, ok := c.auth.(*oauthx.PrivateKeyJwt)
	if !ok {
		return "", errors.New("invalid auth method must be 'private_key_jwt'")
	}

	return privateKeyJwt.GenerateJwtProfileAssertion(oauthx.TokenEndpoint, endpoint)

}

func (c *OIDCClient) GenerateRequestJwt() (string, error) {

	opts := []oauthx.OAuthOption{
		oauthx.ClientIdOpt(c.config.ClientID),
		oauthx.RedirectUriOpt(c.config.RedirectUri),
		oauthx.ScopeOpt(c.config.Scopes),
		oauthx.ResponseTypeCodeOpt(),
		oauthx.AcrValuesOpt(strings.Split(c.config.AcrValues, " ")),
	}

	if c.config.JwtRequestAdditionalParameter != nil {

		// add extra claims to request jwt
		for k, v := range c.config.JwtRequestAdditionalParameter {
			opts = append(opts,
				oauthx.SetOAuthClaimOnly(k, v),
			)
		}
	}

	claims := make(map[string]interface{})
	for _, opt := range opts {
		opt.SetClaim(claims)
	}

	return c.client.PlumbingGenerateRFC9101RequestJwt(claims)
}
