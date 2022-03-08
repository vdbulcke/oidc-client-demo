package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// RefreshTokenFlow renew the refresh token
//
// ref: https://github.com/nonbeing/awsconsoleauth/blob/master/http.go#L46
func (c *OIDCClient) RefreshTokenFlow(refreshToken string, skipIdTokenVerification bool) error {

	token := new(oauth2.Token)
	token.RefreshToken = refreshToken
	token.Expiry = time.Now()

	// TokenSource will refresh the token if needed (which is likely in this
	// use case)
	ts := c.oAuthConfig.TokenSource(context.TODO(), token)

	// get the oauth Token
	oauth2Token, err := ts.Token()
	if err != nil {
		c.logger.Error("Failed to Renew Access Token from refresh token", "refresh-token", refreshToken, "error", err)
		return err
	}

	// Parse Access Token
	accessTokenResponse, err := c.parseAccessTokenResponse(oauth2Token)
	if err != nil {
		c.logger.Error("Error Parsing Access Token", "err", err)
		return err
	}

	// Print Access Token
	accessTokenResponseLog, err := json.MarshalIndent(accessTokenResponse, "", "    ")
	if err != nil {
		c.logger.Error("Error Marchalling access Token Resp", "err", err)
	}

	c.logger.Info("Access Token Response", "Response", string(accessTokenResponseLog))

	// Validate ID Token
	idTokenRaw := accessTokenResponse.IDToken
	if idTokenRaw == "" {
		c.logger.Error("no ID Token Found")
	} else if !skipIdTokenVerification {
		// verify and print idToken
		_, err = c.processIdToken(c.ctx, idTokenRaw)
		if err != nil {
			return err
		}

	}

	// Validate Access Token if JWT
	// and print claims
	if c.config.AccessTokenJwt {
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

	// Validate Access Token if JWT
	// and print claims
	if c.config.RefreshTokenJwt {
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

	// Fetch Userinfo
	err = c.userinfo(oauth2Token)
	if err != nil {
		return err
	}

	return nil

}

// processIdToken Handle idToken call
func (c *OIDCClient) processIdToken(ctx context.Context, idTokenRaw string) (*oidc.IDToken, error) {

	// validate signature agains the JWK
	idToken, err := c.verifier.Verify(c.ctx, idTokenRaw)
	if err != nil {
		c.logger.Error("ID Token validation failed", "err", err)

		return nil, err
	}

	// validate AMR Values
	if !c.validateAMR(idToken) {
		c.logger.Error("Amr not valid", "amrs", c.config.AMRWhitelist)
	}

	// Print IDToken
	var idTokenClaims *json.RawMessage

	// format id Token Claims
	if err := idToken.Claims(&idTokenClaims); err != nil {
		c.logger.Error("Error Parsing ID Token Claims", "err", err)
		return nil, err
	}

	// Print ID Token Claims, and User Info
	idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenClaims", "err", err)
	}
	c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaimsByte))

	return idToken, nil
}

// processAccessToken Handle accessToken JWT validation
func (c *OIDCClient) processAccessToken(ctx context.Context, accessTokenRaw string) (*oidc.IDToken, error) {
	return c.processGenericToken(ctx, accessTokenRaw, "Access")
}

// processRefreshToken Handle Refresh Token JWT validation
func (c *OIDCClient) processRefreshToken(ctx context.Context, refreshTokenRaw string) (*oidc.IDToken, error) {
	return c.processGenericToken(ctx, refreshTokenRaw, "Refresh")
}

func (c *OIDCClient) processGenericToken(ctx context.Context, tokenRaw string, tokenType string) (*oidc.IDToken, error) {
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

	return jwtToken, nil
}

// userinfo Handle userinfo call
func (c *OIDCClient) userinfo(oauth2Token *oauth2.Token) error {
	// Fetch Userinfo
	if !c.config.SkipUserinfo {
		// NOTE: this will detects based on the Content-Type if the userinfo is application/jwt
		//       and if it is JWT it will validate signature agains JWK for the provider
		userInfo, err := c.provider.UserInfo(c.ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			return err
		}

		var userInfoClaims *json.RawMessage
		// format userinfo Claims
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			c.logger.Error("Error Parsing USerinfo Claims", "err", err)
			return err
		}

		userInfoClaimsByte, err := json.MarshalIndent(userInfoClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}

		c.logger.Info("Userinfo Claims", "UserInfoClaims", string(userInfoClaimsByte))

	}

	return nil
}
