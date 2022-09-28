package oidcclient

import pkce "github.com/vdbulcke/oidc-client-demo/oidc-client/internal/pkce"

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (c *OIDCClient) NewNonce(length int) (string, error) {

	// if mock value provider return value
	if c.config.MockNonce != "" {
		return c.config.MockNonce, nil
	}

	// else generate random string
	return c.randString(length)
}

func (c *OIDCClient) NewState(length int) (string, error) {

	// if mock value provider return value
	if c.config.MockState != "" {
		return c.config.MockState, nil
	}

	// else generate random string
	return c.randString(length)
}

func (c *OIDCClient) NewCodeVerifier(length int) (string, error) {

	// if mock value provider return value
	if c.config.MockCodeVerifier != "" {
		return c.config.MockCodeVerifier, nil
	}

	// else generate random string
	return pkce.NewCodeVerifier(length)
}
