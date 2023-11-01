package oidcclient

import (
	"net/url"

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

	oauth2Token, err := c.TokenExchange(params)
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
