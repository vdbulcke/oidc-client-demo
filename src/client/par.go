package oidcclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
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

	body, err := io.ReadAll(resp.Body)
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
//
// RCF9126
//
//	on configured Auth Method
func (c *OIDCClient) generatePARRequest(codeChallenge string, nonce string, state string) (*http.Request, error) {

	scopes := strings.Join(c.config.Scopes, " ")
	parRequestBody := make(map[string]interface{})
	parRequestBody["client_id"] = c.config.ClientID
	parRequestBody["response_type"] = "code"
	parRequestBody["redirect_uri"] = c.config.RedirectUri
	parRequestBody["nonce"] = nonce
	parRequestBody["state"] = state
	if scopes != "" {
		parRequestBody["scope"] = scopes
	}

	claims := map[string]interface{}{}

	claims["state"] = state
	claims["nonce"] = nonce
	// add client_id client_secret param if client_secret_post
	if c.config.AuthMethod == "client_secret_post" {
		c.logger.Debug("par setting client_secret_post")

		parRequestBody["client_secret"] = c.config.ClientSecret

	}
	if c.config.AuthMethod == "private_key_jwt" {

		// Due to historical reasons, there is potential ambiguity regarding the
		// appropriate audience value to use when employing JWT client
		// assertion-based authentication (defined in Section 2.2 of [RFC7523]
		// with "private_key_jwt" or "client_secret_jwt" authentication method
		// names per Section 9 of [OIDC]).  To address that ambiguity, the
		// issuer identifier URL of the authorization server according to
		// [RFC8414] SHOULD be used as the value of the audience.  In order to
		// facilitate interoperability, the authorization server MUST accept its
		// issuer identifier, token endpoint URL, or pushed authorization
		// request endpoint URL as values that identify it as an intended
		// audience.

		// TODO: add config setting to override aud of JWT profile for PAR
		// signedJwt, err := c.GenerateJwtProfile(c.Wellknown.PushedAuthorizationRequestEndpoint)
		signedJwt, err := c.GenerateJwtProfile(c.Wellknown.TokenEndpoint)
		if err != nil {
			c.logger.Error("Failed to generate jwt client_assertion", "err", err)
			return nil, err
		}
		c.logger.Debug("par setting client_assertion", "jwt", signedJwt)
		parRequestBody["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		parRequestBody["client_assertion"] = signedJwt

	}

	if c.config.UsePKCE {
		c.logger.Debug("par setting pkce")

		parRequestBody["code_challenge"] = codeChallenge
		parRequestBody["code_challenge_method"] = c.config.PKCEChallengeMethod
		claims["code_challenge"] = codeChallenge
		claims["code_challenge_method"] = c.config.PKCEChallengeMethod
	}

	if c.config.AcrValues != "" {
		parRequestBody["acr_values"] = c.config.AcrValues
	}

	// RCF9101
	if c.config.UseRequestParameter {

		// https://www.rfc-editor.org/rfc/rfc9126.html#section-3
		// 3.  The "request" Request Parameter

		//    Clients MAY use the "request" parameter as defined in JAR [RFC9101]
		//    to push a Request Object JWT to the authorization server.  The rules
		//    for processing, signing, and encryption of the Request Object as
		//    defined in JAR [RFC9101] apply.  Request parameters required by a
		//    given client authentication method are included in the "application/
		//    x-www-form-urlencoded" request directly and are the only parameters
		//    other than "request" in the form body (e.g., mutual TLS client
		//    authentication [RFC8705] uses the "client_id" HTTP request parameter,
		//    while JWT assertion-based client authentication [RFC7523] uses
		//    "client_assertion" and "client_assertion_type").  All other request
		//    parameters, i.e., those pertaining to the authorization request
		//    itself, MUST appear as claims of the JWT representing the
		//    authorization request.
		paramToKeep := []string{
			"request",
			"client_secret",
			"client_assertion_type",
			"client_assertion",
		}

		if c.config.StrictOIDCAndRCF6749Param {
			// RFC9101
			//
			// The client MAY send the parameters included in the Request Object
			// duplicated in the query parameters as well for backward
			// compatibility, etc.  However, the authorization server supporting
			// this specification MUST only use the parameters included in the
			// Request Object.

			// openid-connect-core
			//
			// So that the request is a valid OAuth 2.0 Authorization Request,
			// values for the "response_type" and "client_id" parameters MUST be
			// included using the OAuth 2.0 request syntax, since they are REQUIRED
			// by OAuth 2.0.  The values for these parameters MUST match those in
			// the Request Object, if present.

			// Even if a "scope" parameter is present in the Request Object value, a
			// "scope" parameter MUST always be passed using the OAuth 2.0 request
			// syntax containing the "openid" scope value to indicate to the
			// underlying OAuth 2.0 logic that this is an OpenID Connect request.

			paramToKeep = append(paramToKeep, "response_type")
			paramToKeep = append(paramToKeep, "client_id")

			if strings.Contains(scopes, "openid") {
				paramToKeep = append(paramToKeep, "scope", "redirect_uri")
			}
		}

		signedJwt, err := c.GenerateRequestJwt(claims)
		if err != nil {
			c.logger.Error("error generating request jwt", err)
			return nil, err
		}

		c.logger.Debug("generated request jwt", "request", signedJwt)
		parRequestBody["request"] = signedJwt

		for k, _ := range parRequestBody {
			// not an allowed parameter
			// delete from request
			// if !stringInSlice(k, paramToKeep) {
			if !slices.Contains(paramToKeep, k) {
				delete(parRequestBody, k)
			}
		}

	}

	if c.config.PARAdditionalParameter != nil {
		for k, v := range c.config.PARAdditionalParameter {
			parRequestBody[k] = v
		}

	}

	params := url.Values{}
	for k, v := range parRequestBody {
		if val, ok := v.(string); ok {
			params.Set(k, val)
		}
	}

	req, err := http.NewRequest(http.MethodPost, c.config.PAREndpoint, strings.NewReader(params.Encode()))
	if err != nil {

		return nil, err
	}

	// Set Content Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	// add client_id client_secret as Basic Auth Header
	// if Auth method is client_secret_post
	if c.config.AuthMethod == "client_secret_basic" {
		c.logger.Debug("par setting client_secret_basic")
		req.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	}

	return req, nil
}
