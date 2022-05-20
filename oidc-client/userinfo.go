package oidcclient

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

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

		// validation 'sub'
		// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
		sub := userInfo.Subject
		if sub == "" {
			c.logger.Error("Missing mandatory 'sub' field")
		}

		// fetch id_token 'sub' from context
		k := subCtxKey("sub")
		idTokenSub := c.ctx.Value(k)
		if idTokenSub != nil {

			// userinfo 'sub' must match id_token 'sub'
			if sub != idTokenSub.(string) {
				c.logger.Error("'sub' fields do not match", "idTokenSub", idTokenSub, "userinfoSub", sub)
			}

		} else {
			c.logger.Error("Could not retrieve id_token 'sub' field from context")
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
