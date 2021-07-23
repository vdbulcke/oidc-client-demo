package oidcclient

import (
	"fmt"
	"strings"
)

// Info Display info about current config
func (c *OIDCClient) Info() {

	conf := fmt.Sprintf("ClientID: %s\nClient_Secret: %s\nRedirect_Uri: %s\nScopes: %s\nIssuer: %s", c.config.ClientID, "************", RedirectUri, strings.Join(c.config.Scopes, ","), c.config.Issuer)

	advanced := fmt.Sprintf("AcrValues: %s\nTokenEndpoint: %s\nAuthorizeEndpoint: %s\nUserinfoEndpoint: %s\nTokenSigningAlg: %s\nSkipTLSVerification: %t", c.config.AcrValues, c.config.TokenEndpoint, c.config.AuthorizeEndpoint, c.config.UserinfoEndpoint, c.config.TokenSigningAlg, c.config.SkipTLSVerification)

	c.logger.Info("OIDC Client", "Config", conf, "Advanced", advanced)
}
