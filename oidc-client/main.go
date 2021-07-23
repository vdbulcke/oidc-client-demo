package oidcclient

import "github.com/hashicorp/go-hclog"

type OIDCClient struct {

	// the config
	config *OIDCClientConfig

	// the Hashicor Logger
	logger hclog.Logger
}

// OIDCClient create a new OIDC Client
func NewOIDCClient(c *OIDCClientConfig, l hclog.Logger) *OIDCClient {
	return &OIDCClient{
		config: c,
		logger: l,
	}
}
