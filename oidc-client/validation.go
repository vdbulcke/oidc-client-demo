package oidcclient

import "github.com/coreos/go-oidc/v3/oidc"

// validateAMR validate 'amr' claim
func (c *OIDCClient) validateAMR(idToken *oidc.IDToken) bool {

	c.logger.Debug("Starting AMR validation")

	// check if need to validate amr values
	if len(c.config.AMRWhitelist) == 0 {
		return true
	}

	// parse amr claims
	var claims struct {
		Amr []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		c.logger.Error("Error parsing amr claims", "id_token", idToken, "err", err)
		return false
	}

	// check if at least one of the whitelisted
	// amr is in the claims
	for _, amr := range c.config.AMRWhitelist {
		if stringInSlice(amr, claims.Amr) {
			return true
		}
	}

	return false

}

// validateACR validate 'acr' claim
func (c *OIDCClient) validateACR(idToken *oidc.IDToken) bool {

	c.logger.Debug("Starting acr validation")

	// check if need to validate amr values
	if len(c.config.ACRWhitelist) == 0 {
		return true
	}

	// parse acr claims
	var claims struct {
		Acr string `json:"acr"`
	}

	if err := idToken.Claims(&claims); err != nil {
		c.logger.Error("Error parsing acr claims", "id_token", idToken, "err", err)
		return false
	}

	// check if at least one of the whitelisted
	// acr is matching the claim
	return stringInSlice(claims.Acr, c.config.ACRWhitelist)

}

