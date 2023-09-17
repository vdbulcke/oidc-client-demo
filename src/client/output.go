package oidcclient

import (
	"fmt"
	"os"
)

// writeOutput Writes Data to file
func (c *OIDCClient) writeOutput(data []byte, file string) error {

	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// SetDefaultOutput  Set default output file name
func (c *OIDCClient) SetDefaultOutput() {
	c.config.AccessTokenRespFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "access_token_resp.json")
	c.config.IDTokenFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "id_token.json")
	c.config.UserinfoFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "userinfo.json")
	c.config.AccessTokenFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "access_token.json")
	c.config.RefreshTokenFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "refresh_token.json")
	c.config.IntrospectFile = fmt.Sprintf("%s/%s", c.config.OutputDir, "introspect.json")
}
