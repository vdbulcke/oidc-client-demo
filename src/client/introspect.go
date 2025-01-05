package oidcclient

import (
	"encoding/json"
	"errors"

	"github.com/vdbulcke/oauthx"
)

// IntrospectToken introspect the token
func (c *OIDCClient) IntrospectToken(token string) error {

	req := oauthx.NewIntrospectionRequest(
		oauthx.TokenOpt(token),
		// oauthx.TokenTypeHintOpt(oauthx.TokenTypeRefreshToken),
	)

	resp, err := c.client.DoIntrospectionRequest(c.ctx, req)
	if err != nil {
		c.logger.Error("error making introspect request", "error", err)

		var httpErr *oauthx.HttpErr
		if errors.As(err, &httpErr) {
			c.logger.Error("http error", "response_code", httpErr.StatusCode, "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			rfc6749Err, err := httpErr.AsRFC6749Error()
			if err == nil {
				c.logger.Error("rfc6749 err", "error", rfc6749Err.Error, "error_description", rfc6749Err.ErrorDescription, "error_uri", rfc6749Err.ErrorUri)
			}
		}
		return err
	}

	var customClaims struct {
		Foo string `json:"foo"`
		Bar map[string]interface{}
	}

	err = resp.UnmarshallClaims(&customClaims)

	// snippet only
	var result json.RawMessage
	err = json.Unmarshal(resp.RawPayload, &result)
	if err != nil {
		// c.logger.Error("error parsing introspect response", "body", string(body), "error", err)
		return err
	}

	// print response
	introspectResp, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		c.logger.Error("Error Marchalling introspect Resp", "err", err)
	}

	c.logger.Info("Introspect Response", "Response", string(introspectResp))

	// Raw Response

	if c.config.OutputEnabled {
		err = c.writeOutput(introspectResp, c.config.IntrospectFile)
		if err != nil {
			c.logger.Error("Error Writing introspect file", "error", err)
		}
	}

	return nil
}
