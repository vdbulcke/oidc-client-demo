package oidcclient

import (
	"context"
	"encoding/json"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// RefreshTokenFlow renew the refresh token
//
// ref: https://github.com/nonbeing/awsconsoleauth/blob/master/http.go#L46
func (c *OIDCClient) RefreshTokenFlow(refreshToken string, skipUserinfo bool, skipIdTokenVerification bool) error {

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
	var idToken *oidc.IDToken
	idTokenRaw := accessTokenResponse.IDToken
	if idTokenRaw == "" {
		c.logger.Error("no ID Token Found")
	} else if !skipIdTokenVerification {

		// validate signature agains the JWK
		idToken, err = c.verifier.Verify(c.ctx, idTokenRaw)
		if err != nil {
			c.logger.Error("ID Token validation failed", "err", err)

			return err
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
			return err
		}

		// Print ID Token Claims, and User Info
		idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}
		c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaimsByte))
	}

	// Fetch Userinfo
	if !skipUserinfo {
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
