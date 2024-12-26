package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// processAccessToken Handle accessToken JWT validation
func (c *OIDCClient) processAccessToken(ctx context.Context, accessTokenRaw string) error {
	return c.processGenericToken(ctx, accessTokenRaw, "Access")
}

// processRefreshToken Handle Refresh Token JWT validation
func (c *OIDCClient) processRefreshToken(ctx context.Context, refreshTokenRaw string) error {
	return c.processGenericToken(ctx, refreshTokenRaw, "Refresh")
}

func (c *OIDCClient) processGenericToken(ctx context.Context, tokenRaw string, tokenType string) error {

	// parse header
	// header, headerClaims, err := c.parseJWTHeader(tokenRaw)
	header, _, err := c.parseJWTHeader(tokenRaw)
	if err != nil {
		c.logger.Error(fmt.Sprintf("error parsing %s token header", tokenType), "error", err)
	} else {
		// pretty print header
		c.logger.Info(fmt.Sprintf("%s Token header", tokenType), "header", header)
	}

	var supportedSigAlgs []jose.SignatureAlgorithm

	// default to provider metadata supported alg
	for _, alg := range c.client.GetWellknown().IDTokenSigningAlgValuesSupported {
		supportedSigAlgs = append(supportedSigAlgs, jose.SignatureAlgorithm(alg))
	}

	if len(supportedSigAlgs) == 0 {
		// If no algorithms were specified by both the config and discovery, default
		// to the one mandatory algorithm "RS256".
		supportedSigAlgs = []jose.SignatureAlgorithm{jose.RS256}
	}

	jws, err := jose.ParseSigned(tokenRaw, supportedSigAlgs)
	if err != nil {
		return fmt.Errorf("id_token: signature validation malformed jwt: %w", err)
	}

	ks := c.client.GetJWKSet()

	err = ks.VerifySignature(c.ctx, jws)
	if err != nil {

		c.logger.Error(fmt.Sprintf("%s Token validation failed", tokenType), "err", err)
		return err
	}

	payload := jws.UnsafePayloadWithoutVerification()
	// Print token
	var accessTokenClaims *json.RawMessage

	// format access Token Claims
	if err := json.Unmarshal(payload, &accessTokenClaims); err != nil {
		c.logger.Error(fmt.Sprintf("Error Parsing %s Token Claims", tokenType), "err", err)
		return err
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

	return nil
}
