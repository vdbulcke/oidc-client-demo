package oidcclient

import (
	"encoding/json"

	"github.com/vdbulcke/oauthx"
)

// userinfo Handle userinfo call
func (c *OIDCClient) userinfo(userInfo *oauthx.Userinfo) error {

	var userInfoClaims *json.RawMessage
	// format userinfo Claims
	if err := userInfo.UnmarshallClaims(&userInfoClaims); err != nil {
		c.logger.Error("Error Parsing USerinfo Claims", "err", err)
		return err
	}

	userInfoClaimsByte, err := json.MarshalIndent(userInfoClaims, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenClaims", "err", err)
	}

	c.logger.Info("Userinfo Claims", "UserInfoClaims", string(userInfoClaimsByte))
	if c.config.OutputEnabled {
		err = c.writeOutput(userInfoClaimsByte, c.config.UserinfoFile)
		if err != nil {
			c.logger.Error("Error Writing Userinfo file", "error", err)
		}
	}

	return nil
}
