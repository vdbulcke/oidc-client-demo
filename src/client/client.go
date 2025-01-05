package oidcclient

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/vdbulcke/oauthx"
)

// JSONAccessTokenResponse ...
type JSONAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Nonce        string `json:"nonce"`
	// NOTE: this is reformatted as Human readable time
	ExpiresInHumanReadable string `json:"expires_in_human_readable"`
}

func (c *OIDCClient) setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	ttl := 15 * time.Minute
	cookie := &http.Cookie{
		Name:  name,
		Value: value,
		// MaxAge:   int(time.Hour.Seconds()),
		MaxAge:   int(ttl.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

func (c *OIDCClient) processAccessTokenResponse(tokenResponse *oauthx.TokenResponse) {

	c.logger.Info("AccessToken expiration", "exp", tokenResponse.GetExpiration())

	var accessTokenResponse json.RawMessage
	err := json.Unmarshal(tokenResponse.Raw, &accessTokenResponse)
	if err != nil {
		c.logger.Error("Error Marchalling access Token Resp", "err", err)
	}

	accessTokenResponseLog, err := json.MarshalIndent(accessTokenResponse, "", "    ")
	if err != nil {
		c.logger.Error("Error Marchalling access Token Resp", "err", err)
	}

	c.logger.Info("Access Token Response", "Response", string(accessTokenResponseLog))
	if c.config.OutputEnabled {
		err = c.writeOutput(accessTokenResponseLog, c.config.AccessTokenRespFile)
		if err != nil {
			c.logger.Error("Error Writing Access Token Response file", "error", err)
		}
	}

}

func (c *OIDCClient) GetLogger() hclog.Logger {
	return c.logger
}
