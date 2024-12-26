package oidcclient

import (
	"errors"

	"github.com/vdbulcke/oauthx"
)

func (c *OIDCClient) EndSession(token, postLogoutRedirectUri string) error {

	req := oauthx.NewEndSessionRequest(
		oauthx.ClientIdOpt(c.config.ClientID),
		oauthx.IdTokenHintOpt(token),
	)

	if postLogoutRedirectUri != "" {
		req.AddOpts(
			oauthx.PostLogoutRedirectUriOpt(postLogoutRedirectUri),
		)
	}

	resp, err := c.client.DoEndSessionRequest(c.ctx, req)
	if err != nil {
		c.logger.Error("error making endsession request", "error", err)

		var httpErr *oauthx.HttpErr
		if errors.As(err, &httpErr) {
			c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
		}
		return err
	}

	c.logger.Info("endSession success", "resp", resp)
	return nil
}
