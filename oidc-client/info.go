package oidcclient

import (
	"fmt"
	"strings"
)

// Info Display info about current config
func (c *OIDCClient) Info() {

	conf := fmt.Sprintf("ClientID: %s\nClient_Secret: %s\nRedirect_Uri: %s\nScopes: %s\nIssuer: %s", c.config.ClientID, "************", c.config.RedirectUri, strings.Join(c.config.Scopes, ","), c.config.Issuer)

	advanced := fmt.Sprintf("AcrValues: %s\nTokenEndpoint: %s\nAuthorizeEndpoint: %s\nTokenSigningAlg: %s\nSkipTLSVerification: %t\nJwksEndpoint: %s", c.config.AcrValues, c.config.TokenEndpoint, c.config.AuthorizeEndpoint, c.config.TokenSigningAlg, c.config.SkipTLSVerification, c.config.JwksEndpoint)

	c.logger.Info("OIDC Client", "Config", conf, "Advanced", advanced, "Amrs", c.config.AMRWhitelist)
}
