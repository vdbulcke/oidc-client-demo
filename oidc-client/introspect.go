package oidcclient

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type expirationTime int64

// IntrospectResponse
// standard fields from rfc7662 https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type IntrospectResponse struct {
	Active bool `json:"active"`

	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`

	Exp expirationTime `json:"exp,omitempty"`
	Iat expirationTime `json:"iat,omitempty"`
	Nbf expirationTime `json:"nbf,omitempty"`

	Sub    string `json:"sub,omitempty"`
	Aud    string `json:"aud,omitempty"`
	Issuer string `json:"iss,omitempty"`
	Jti    string `json:"jti,omitempty"`

	// Human readable Timestamp
	Expiry    time.Time `json:"expiry,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
}

// IntrospectToken introspect the token
func (c *OIDCClient) IntrospectToken(token string) error {

	// create HTTP Introspect request
	req, err := c.generateIntrospectRequest(token)
	if err != nil {
		c.logger.Error("error creating introspect request", "error", err)
		return err
	}

	// make HTTP Introspect Request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.logger.Error("error making introspect request", "error", err)
		return err
	}

	if c.logger.IsDebug() {
		c.logger.Debug("Raw Introspect Response", "resp", resp)
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		c.logger.Error("error reading introspect response", "error", err)
		return err
	}

	// snippet only
	var result IntrospectResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		c.logger.Error("error parsing introspect response", "body", string(body), "error", err)
	}

	// Set human redeable time

	if result.Exp != 0 {

		result.Expiry = time.Unix(int64(result.Exp), 0)
	}

	if result.Iat != 0 {
		result.IssuedAt = time.Unix(int64(result.Iat), 0)
	}

	if result.Nbf != 0 {
		result.NotBefore = time.Unix(int64(result.Nbf), 0)
	}

	// print response
	introspectResp, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		c.logger.Error("Error Marchalling introspect Resp", "err", err)
	}

	c.logger.Info("Introspect Response", "Response", string(introspectResp))

	// Raw Response
	var raw interface{}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		c.logger.Error("error parsing introspect response", "body", string(body), "error", err)
	}

	// pretty print response
	introspectRaw, err := json.MarshalIndent(raw, "", "    ")
	if err != nil {
		c.logger.Error("Error Marchalling introspect Resp", "err", err)
	}

	c.logger.Info("Introspect Raw", "raw", string(introspectRaw))

	if c.config.OutputEnabled {
		err = c.writeOutput(introspectRaw, c.config.IntrospectFile)
		if err != nil {
			c.logger.Error("Error Writing introspect file", "error", err)
		}
	}

	return nil
}

// generateIntrospectRequest generate the introspect req based
//  on configured Auth Method
func (c *OIDCClient) generateIntrospectRequest(token string) (*http.Request, error) {
	introspectParamValues := url.Values{}
	introspectParamValues.Set("token", token)

	// add client_id client_secret param if client_secret_post
	if c.config.AuthMethod == "client_secret_post" {
		c.logger.Debug("setting client_secret_post")
		introspectParamValues.Set("client_id", c.config.ClientID)
		introspectParamValues.Set("client_secret", c.config.ClientSecret)

	}

	req, err := http.NewRequest(http.MethodPost, c.config.IntrospectEndpoint, strings.NewReader(introspectParamValues.Encode()))
	if err != nil {

		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// add client_id client_secret as Basic Auth Header
	// if Auth method is client_secret_post
	if c.config.AuthMethod == "client_secret_basic" {
		c.logger.Debug("setting client_secret_basic")
		req.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	}

	return req, nil
}
