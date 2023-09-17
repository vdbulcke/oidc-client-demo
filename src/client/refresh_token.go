package oidcclient

import (
	"context"
	"net/url"

	internaloauth2 "github.com/vdbulcke/oidc-client-demo/src/client/internal/oauth2"
	"golang.org/x/oauth2"
)

// RefreshTokenFlow renew the refresh token
//
// ref: https://github.com/nonbeing/awsconsoleauth/blob/master/http.go#L46
func (c *OIDCClient) RefreshTokenFlow(refreshToken string, skipIdTokenVerification bool) error {

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	if c.config.AuthMethod == "private_key_jwt" {

		// signedJwt, err := c.GenerateJwtProfile(c.config.IntrospectEndpoint)
		signedJwt, err := c.GenerateJwtProfile(c.Wellknown.TokenEndpoint)
		if err != nil {
			c.logger.Error("Failed to generate jwt client_assertion", "err", err)
			return err
		}
		c.logger.Debug("introspect setting client_assertion", "jwt", signedJwt)
		params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		params.Set("client_assertion", signedJwt)

	}

	// token := new(oauth2.Token)
	// token.RefreshToken = refreshToken
	// token.Expiry = time.Now()

	// TokenSource will refresh the token if needed (which is likely in this
	// use case)
	// ts := c.oAuthConfig.TokenSource(context.TODO(), token)

	// get the oauth Token
	// oauth2Token, err := ts.Token()
	oauth2Token, err := internaloauth2.RetrieveToken(context.TODO(), c.config.ClientID, c.config.ClientSecret, c.Wellknown.TokenEndpoint, params, c.oAuthConfig.Endpoint.AuthStyle)
	if err != nil {
		c.logger.Error("Failed to Renew Access Token from refresh token", "refresh-token", refreshToken, "error", err)
		return err
	}

	// Parse Access Token
	accessTokenResponse := &JSONAccessTokenResponse{
		AccessToken:            oauth2Token.AccessToken,
		ExpiresInHumanReadable: oauth2Token.Expiry.String(),
		TokenType:              oauth2Token.TokenType,
		RefreshToken:           oauth2Token.RefreshToken,
	}

	// Parsing Extra field

	// Parsing IdToken
	idToken, ok := oauth2Token.Extra("id_token").(string)
	if ok {

		accessTokenResponse.IDToken = idToken
	}

	// Parsing Nonce
	nonce, ok := oauth2Token.Extra("nonce").(string)
	if ok {

		accessTokenResponse.Nonce = nonce
	}

	// Parsing Scopes
	scope, ok := oauth2Token.Extra("scope").(string)
	if ok {

		accessTokenResponse.Scope = scope
	}
	// Print Access Token
	c.processAccessTokenResponse(accessTokenResponse)

	// Validate ID Token
	idTokenRaw := accessTokenResponse.IDToken
	if idTokenRaw == "" {
		c.logger.Error("no ID Token Found")
	} else if !skipIdTokenVerification {
		// verify and print idToken
		_, err = c.processIdToken(idTokenRaw)
		if err != nil {
			return err
		}

	}

	// Validate Access Token if JWT
	// and print claims
	if c.config.AccessTokenJwt {
		// try to parse access token as JWT
		accessTokenRaw := accessTokenResponse.AccessToken
		if accessTokenRaw == "" {
			c.logger.Error("no Access Token Found")
		} else {
			// validate signature against the JWK
			_, err := c.processAccessToken(c.ctx, accessTokenRaw)
			if err != nil {
				c.logger.Error("Access Token validation failed", "err", err)
				return err
			}
		}
	}

	// Validate Access Token if JWT
	// and print claims
	if c.config.RefreshTokenJwt {
		refreshTokenRaw := accessTokenResponse.RefreshToken
		if refreshTokenRaw == "" {
			c.logger.Error("no Refresh Token Found")
		} else {
			// validate signature against the JWK
			_, err := c.processRefreshToken(c.ctx, refreshTokenRaw)
			if err != nil {
				c.logger.Error("Refresh Token validation failed", "err", err)
				return err
			}
		}
	}

	tok := &oauth2.Token{
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		TokenType:    oauth2Token.TokenType,
		Expiry:       oauth2Token.Expiry,
	}
	// Fetch Userinfo
	err = c.userinfo(tok)
	if err != nil {
		return err
	}

	return nil

}
