package oidcclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2
type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (c *OIDCClient) DoPARRequest(codeChallenge string, nonce string, state string) (*PARResponse, error) {

	req, err := c.generatePARRequest(codeChallenge, nonce, state)
	if err != nil {
		return nil, err
	}

	// make HTTP Introspect Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.logger.Error("error making PAR request", "error", err)
		return nil, err
	}

	if c.logger.IsDebug() {
		c.logger.Debug("Raw PAR Response", "resp", resp)
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		c.logger.Error("error reading PAR response", "error", err)
		return nil, err
	}

	// standard indicates successful request is 201 and not 200
	if resp.StatusCode != 201 {
		c.logger.Error("PAR Invalid status code", "status", resp.StatusCode, "body", string(body))
		return nil, errors.New("PAR response")
	}

	var parResp PARResponse
	err = json.Unmarshal(body, &parResp)
	if err != nil {
		return nil, err
	}

	return &parResp, nil

}

// generatePARRequest generate the introspect req based
//  on configured Auth Method
func (c *OIDCClient) generatePARRequest(codeChallenge string, nonce string, state string) (*http.Request, error) {

	parRequestBody := make(map[string]interface{})
	parRequestBody["client_id"] = c.config.ClientID
	parRequestBody["response_type"] = "code"
	parRequestBody["scope"] = strings.Join(c.config.Scopes, " ")
	parRequestBody["redirect_uri"] = c.config.RedirectUri
	parRequestBody["nonce"] = nonce
	parRequestBody["state"] = state

	// add client_id client_secret param if client_secret_post
	if c.config.AuthMethod == "client_secret_post" {
		c.logger.Debug("par setting client_secret_post")

		parRequestBody["client_secret"] = c.config.ClientSecret

	}

	if c.config.UsePKCE {
		c.logger.Debug("par setting pkce")

		parRequestBody["code_challenge"] = codeChallenge
		parRequestBody["code_challenge_method"] = c.config.PKCEChallengeMethod
	}

	if c.config.AcrValues != "" {
		parRequestBody["acr_values"] = c.config.AcrValues
	}

	if c.config.PARAdditionalParameter != nil {

		for k, v := range c.config.PARAdditionalParameter {
			parRequestBody[k] = v
		}

	}

	payloadRaw, err := json.Marshal(parRequestBody)
	if err != nil {
		c.logger.Error("error formatting PAR request", "error", err)
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.config.PAREndpoint, bytes.NewBuffer(payloadRaw))
	if err != nil {

		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/json")

	// add client_id client_secret as Basic Auth Header
	// if Auth method is client_secret_post
	if c.config.AuthMethod == "client_secret_basic" {
		c.logger.Debug("par setting client_secret_basic")
		req.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	}

	return req, nil
}
