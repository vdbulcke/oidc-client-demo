package oidcclient

import (
	"context"
	"encoding/json"

	"github.com/coreos/go-oidc/v3/oidc"
)

// processIdToken Handle idToken call
func (c *OIDCClient) processIdToken(idTokenRaw string) (*oidc.IDToken, error) {

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

	// Print ID Token Claims
	idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenClaims", "err", err)
	}
	c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaimsByte))

	// Save sub from ID Token into context
	// for Userinfo validation
	sub := idToken.Subject
	c.ctx = context.WithValue(c.ctx, "sub", sub)

	return idToken, nil
}
