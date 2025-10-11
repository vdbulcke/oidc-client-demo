package oidcclient

import (
	"errors"
	"slices"

	"github.com/vdbulcke/oauthx"
)

// TokenExchangeFlow rfc8693 TokenExchange
func (c *OIDCClient) TokenExchangeFlow(subjectToken, subjectTokenType, requestedTokenType, actorToken, actorTokenType string) error {

	req := oauthx.NewTokenRequest(
		oauthx.TokenExchangeGrantTypeOpt(),
		oauthx.SubjectTokenOpt(subjectToken),
		oauthx.SubjectTokenTypeOpt(subjectTokenType),
	)

	if requestedTokenType != "" {
		req.AddOpts(oauthx.RequestedTokenTypeOpt(requestedTokenType))
	}

	if actorToken != "" {
		req.AddOpts(oauthx.ActorTokenOpt(actorToken))
	}
	if actorTokenType != "" {
		req.AddOpts(oauthx.ActorTokenTypeOpt(actorTokenType))
	}

	for a := range slices.Values(c.config.Audience) {
		req.AddOpts(oauthx.AudienceOpt(a))
	}

	if len(c.config.Scopes) > 0 {
		req.AddOpts(oauthx.ScopeOpt(c.config.Scopes...))
	}

	tokenResp, err := c.client.DoTokenRequest(c.ctx, req)
	if err != nil {
		c.logger.Error("Failed to token exchange", "err", err)

		var httpErr *oauthx.HttpErr
		if errors.As(err, &httpErr) {
			c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
		}

		return err
	}

	// Print Access Token
	c.processAccessTokenResponse(tokenResp)

	var tokenExchangeResp oauthx.TokenExchangeResponse
	err = tokenResp.UnmarshallPayload(&tokenExchangeResp)
	if err != nil {
		c.logger.Error("Failed to token exchange", "err", err)
		return err
	}

	switch tokenExchangeResp.IssuedTokenType {
	case oauthx.TokenTypeIdentifierIDToken:
		// use default options
		idToken, err := c.client.ParseIDToken(c.ctx, tokenExchangeResp.AccessToken)
		if err != nil {
			c.logger.Error("ID Token validation failed", "err", err)
			return err
		}

		// print idToken
		c.processIdToken(idToken)

	case oauthx.TokenTypeIdentifierAccessToken:
		// Validate Access Token if JWT
		// and print claims
		if c.config.AccessTokenJwt {
			// try to parse access token as JWT
			accessTokenRaw := tokenExchangeResp.AccessToken
			if accessTokenRaw == "" {
				c.logger.Error("no Access Token Found")
			} else {
				// validate signature against the JWK
				err := c.processAccessToken(c.ctx, accessTokenRaw)
				if err != nil {
					c.logger.Error("Access Token validation failed", "err", err)
					return err
				}

			}
		}

	default:
		c.logger.Warn("unsupported token type", "issued_token_type", tokenExchangeResp.IssuedTokenType)
	}

	// Validate refresh Token if JWT
	// and print claims
	if c.config.RefreshTokenJwt {
		// try to parse refresh token as JWT
		refreshTokenRaw := tokenResp.RefreshToken
		if refreshTokenRaw == "" {
			c.logger.Error("no Refresh Token Found")
		} else {
			// validate signature against the JWK
			err := c.processRefreshToken(c.ctx, refreshTokenRaw)
			if err != nil {
				c.logger.Error("Refresh Token validation failed", "err", err)
				return err
			}

		}
	}

	return nil

}
