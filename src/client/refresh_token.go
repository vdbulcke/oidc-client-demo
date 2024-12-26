package oidcclient

import (
	"errors"

	"github.com/vdbulcke/oauthx"
)

// RefreshTokenFlow renew the refresh token
//
// ref: https://github.com/nonbeing/awsconsoleauth/blob/master/http.go#L46
func (c *OIDCClient) RefreshTokenFlow(refreshToken string, skipIdTokenVerification bool) error {

	req := oauthx.NewTokenRequest(
		oauthx.RefreshTokenGrantTypeOpt(),
		oauthx.RefreshTokenOpt(refreshToken),
	)

	tokenResp, err := c.client.DoTokenRequest(c.ctx, req)
	if err != nil {
		c.logger.Error("Failed to Renew Access Token from refresh token", "err", err)

		var httpErr *oauthx.HttpErr
		if errors.As(err, &httpErr) {
			c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
		}

		return err
	}

	// Print Access Token
	c.processAccessTokenResponse(tokenResp)

	if tokenResp.IDToken != "" {

		// use default options
		idToken, err := c.client.ParseIDToken(c.ctx, tokenResp.IDToken)
		if err != nil {
			c.logger.Error("ID Token validation failed", "err", err)
			return err
		}

		// print idToken
		c.processIdToken(idToken)
	}

	// Validate Access Token if JWT
	// and print claims
	if c.config.AccessTokenJwt {
		// try to parse access token as JWT
		accessTokenRaw := tokenResp.AccessToken
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

	// Fetch Userinfo
	if !c.config.SkipUserinfo {
		userinfo, err := c.client.DoUserinfoRequest(c.ctx, tokenResp.AccessToken)
		if err != nil {

			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}
			return err
		}

		_ = c.userinfo(userinfo)
	}

	return nil

}
