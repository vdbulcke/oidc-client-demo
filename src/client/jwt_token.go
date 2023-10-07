package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// processAccessToken Handle accessToken JWT validation
func (c *OIDCClient) processAccessToken(ctx context.Context, accessTokenRaw string) (*oidc.IDToken, error) {
	return c.processGenericToken(ctx, accessTokenRaw, "Access")
}

// processRefreshToken Handle Refresh Token JWT validation
func (c *OIDCClient) processRefreshToken(ctx context.Context, refreshTokenRaw string) (*oidc.IDToken, error) {
	return c.processGenericToken(ctx, refreshTokenRaw, "Refresh")
}

func (c *OIDCClient) processGenericToken(ctx context.Context, tokenRaw string, tokenType string) (*oidc.IDToken, error) {

	// parse header
	// header, headerClaims, err := c.parseJWTHeader(tokenRaw)
	header, _, err := c.parseJWTHeader(tokenRaw)
	if err != nil {
		c.logger.Error(fmt.Sprintf("error parsing %s token header", tokenType), "error", err)
	} else {
		// pretty print header
		c.logger.Info(fmt.Sprintf("%s Token header", tokenType), "header", header)
	}

	// validate signature against the JWK
	jwtToken, err := c.jwkVerifier.Verify(c.ctx, tokenRaw)
	if err != nil {
		c.logger.Error(fmt.Sprintf("%s Token validation failed", tokenType), "err", err)

		return nil, err
	}

	// Print token
	var accessTokenClaims *json.RawMessage

	// format access Token Claims
	if err := jwtToken.Claims(&accessTokenClaims); err != nil {
		c.logger.Error(fmt.Sprintf("Error Parsing %s Token Claims", tokenType), "err", err)
		return nil, err
	}

	// Print Access Token Claims, and User Info
	accessTokenClaimsByte, err := json.MarshalIndent(accessTokenClaims, "", "    ")
	if err != nil {
		c.logger.Error(fmt.Sprintf("Could not parse %sToken Claims", tokenType), "err", err)
	}
	c.logger.Info(fmt.Sprintf("%s Token Claims", tokenType), "TokenClaims", string(accessTokenClaimsByte))

	if c.config.OutputEnabled {
		var file string
		if tokenType == "Access" {
			file = c.config.AccessTokenFile
		} else {
			file = c.config.RefreshTokenFile
		}

		err = c.writeOutput(accessTokenClaimsByte, file)
		if err != nil {
			c.logger.Error(fmt.Sprintf("Error writing %s Token ", tokenType), "error", err)
		}
	}

	return jwtToken, nil
}
