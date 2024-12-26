package oidcclient

import (
	"encoding/json"

	"github.com/vdbulcke/oauthx"
)

// processIdToken Handle idToken call
func (c *OIDCClient) processIdToken(idToken *oauthx.IDToken) {

	var header json.RawMessage
	if err := json.Unmarshal(idToken.RawHeader, &header); err != nil {
		c.logger.Error("Error Parsing ID Token header", "err", err)
		return
	}

	idTokenHeaderByte, err := json.MarshalIndent(header, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenheader", "err", err)
	}
	// Print IDToken
	var idTokenClaims *json.RawMessage

	// format id Token Claims
	if err := idToken.UnmarshallClaims(&idTokenClaims); err != nil {
		c.logger.Error("Error Parsing ID Token Claims", "err", err)
		return
	}

	// Print ID Token Claims
	idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenClaims", "err", err)
	}
	c.logger.Info("IDToken Claims", "header", string(idTokenHeaderByte), "IDTokenClaims", string(idTokenClaimsByte))

	if c.config.OutputEnabled {
		err = c.writeOutput(idTokenClaimsByte, c.config.IDTokenFile)
		if err != nil {
			c.logger.Error("Error Writing IDToken file", "error", err)
		}
	}

}
