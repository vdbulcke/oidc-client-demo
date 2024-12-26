package oidcclient

import (
	"errors"

	"github.com/vdbulcke/oauthx"
)

func (c *OIDCClient) Revoke(token string) error {

	req := oauthx.NewRevokeRequest(
		oauthx.TokenOpt(token),
	)

	err := c.client.DoRevokeRequest(c.ctx, req)
	if err != nil {
		c.logger.Error("error making revocation request", "error", err)

		var httpErr *oauthx.HttpErr
		if errors.As(err, &httpErr) {
			c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
		}
		return err
	}
	return nil
}
