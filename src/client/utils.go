package oidcclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	pkce "github.com/vdbulcke/oidc-client-demo/src/client/internal/pkce"
)

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

func (c *OIDCClient) NewCodeChallenge(codeVerifier string) (string, error) {

	// else generate random string
	return pkce.NewCodeChallenge(codeVerifier, c.config.PKCEChallengeMethod)

}
func (c *OIDCClient) parseJWTHeader(rawToken string) (string, error) {

	parts := strings.Split(rawToken, ".")
	// header must be the first part
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf(" malformed jwt header: %v", err)
	}

	var parsedHeader map[string]string
	if err := json.Unmarshal(header, &parsedHeader); err != nil {
		return "", fmt.Errorf("failed to unmarshal jwt header: %v", err)
	}

	// pretty output
	parsedHeaderByte, err := json.MarshalIndent(parsedHeader, "", "    ")
	if err != nil {
		c.logger.Error("Could not marshal jwt header", "err", err)
		return "", err
	}

	return string(parsedHeaderByte), nil
}
