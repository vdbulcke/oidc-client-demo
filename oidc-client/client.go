package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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

func (c *OIDCClient) randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *OIDCClient) setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

func (c *OIDCClient) parseAccessTokenResponse(oauth2Token *oauth2.Token) (*JSONAccessTokenResponse, error) {
	// common logger text
	commonLoggerText := "Access Token Response"

	// Parse Access Token
	accessToken := oauth2Token.AccessToken
	if c.logger.IsDebug() {
		c.logger.Debug(commonLoggerText, "access_token", accessToken)
	}

	// Parse Token Type
	tokenType := oauth2Token.Type()
	if c.logger.IsDebug() {
		c.logger.Debug(commonLoggerText, "token_type", tokenType)
	}

	// Parse (and format) Token Expiration
	tokenExpiration := oauth2Token.Expiry.String()
	if c.logger.IsDebug() {
		c.logger.Debug(commonLoggerText, "expires_in", tokenExpiration)
	}

	// Parse (and format) Token Expiration
	refreshToken := oauth2Token.RefreshToken
	if c.logger.IsDebug() {
		c.logger.Debug(commonLoggerText, "refresh_token", refreshToken)
	}

	// create the base JSON Access Token obj
	jsonAccessTokenResp := &JSONAccessTokenResponse{
		AccessToken:            accessToken,
		ExpiresInHumanReadable: tokenExpiration,
		TokenType:              tokenType,
		RefreshToken:           refreshToken,
	}

	// Parsing Extra field

	// Parsing IdToken
	idToken, ok := oauth2Token.Extra("id_token").(string)
	if ok {
		if c.logger.IsDebug() {
			c.logger.Debug(commonLoggerText, "id_token", idToken)
		}

		jsonAccessTokenResp.IDToken = idToken
	}

	// Parsing Nonce
	nonce, ok := oauth2Token.Extra("nonce").(string)
	if ok {
		if c.logger.IsDebug() {
			c.logger.Debug(commonLoggerText, "nonce", nonce)
		}

		jsonAccessTokenResp.Nonce = nonce
	}

	// Parsing Scopes
	scope, ok := oauth2Token.Extra("scope").(string)
	if ok {
		if c.logger.IsDebug() {
			c.logger.Debug(commonLoggerText, "scope", scope)
		}

		jsonAccessTokenResp.Scope = scope
	}

	return jsonAccessTokenResp, nil
}

func (c *OIDCClient) OIDCAuthorizationCodeFlow() error {

	ctx := context.Background()

	// skipping the TLS verification endpoint could be self signed
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: c.config.SkipTLSVerification,
	}

	// provider := c.newProvider(ctx)
	provider, err := oidc.NewProvider(ctx, c.config.Issuer)
	if err != nil {
		c.logger.Error("Could create OIDC provider form WellKnown endpoint", "err", err)
		return err
	}

	oidcConfig := &oidc.Config{
		ClientID:             c.config.ClientID,
		SupportedSigningAlgs: []string{c.config.TokenSigningAlg},
	}
	verifier := provider.Verifier(oidcConfig)

	// new OAuth2 Config
	oAuthConfig := oauth2.Config{
		ClientID:     c.config.ClientID,
		ClientSecret: c.config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.config.RedirectUri,
		Scopes:       c.config.Scopes,
	}

	// override setting from well-known endpoint
	if c.config.AuthorizeEndpoint != "" {
		oAuthConfig.Endpoint.AuthURL = c.config.AuthorizeEndpoint
	}
	if c.config.TokenEndpoint != "" {
		oAuthConfig.Endpoint.TokenURL = c.config.TokenEndpoint
	}

	// generate state and none
	state, err := c.randString(6)
	if err != nil {
		c.logger.Error("Could not generate state", "err", err)
		return err
	}

	nonce, err := c.randString(6)
	if err != nil {
		c.logger.Error("Could not generate nonce", "err", err)
		return err
	}

	// setting Authorize call options
	authNonceOption := oauth2.SetAuthURLParam("nonce", nonce)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		c.setCallbackCookie(w, r, "state", state)
		c.setCallbackCookie(w, r, "nonce", nonce)

		// authorize URL
		var authorizeURL string
		if c.config.AcrValues != "" {
			acrValuesOption := oauth2.SetAuthURLParam("acr_values", c.config.AcrValues)
			authorizeURL = oAuthConfig.AuthCodeURL(state, authNonceOption, acrValuesOption)
		} else {
			authorizeURL = oAuthConfig.AuthCodeURL(state, authNonceOption)
		}

		http.Redirect(w, r, authorizeURL, http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		stateCookie, err := r.Cookie("state")
		if err != nil {
			c.logger.Error("state not found", "err", err)
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != stateCookie.Value {
			c.logger.Error("state did not match", "cookie_state", stateCookie.Value, "query_state", r.URL.Query().Get("state"))
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		// get authZ code
		authZCode := r.URL.Query().Get("code")
		c.logger.Info("Received AuthZ Code", "code", authZCode)

		// Access Token Response
		oauth2Token, err := oAuthConfig.Exchange(ctx, authZCode)
		if err != nil {
			c.logger.Error("Failed to get Access Token", "err", err)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Parse Access Token
		accessTokenResponse, err := c.parseAccessTokenResponse(oauth2Token)
		if err != nil {
			c.logger.Error("Error Parsing Access Token", "err", err)
			http.Error(w, "Error Parsing Access Token", http.StatusBadRequest)
			return
		}

		// Print Access Token
		accessTokenResponseLog, err := json.MarshalIndent(accessTokenResponse, "", "    ")
		if err != nil {
			c.logger.Error("Error Marchalling access Token Resp", "err", err)
		}

		c.logger.Info("Access Token Response", "Response", string(accessTokenResponseLog))

		// Validate ID Token
		var idToken *oidc.IDToken
		idTokenRaw := accessTokenResponse.IDToken
		if idTokenRaw == "" {
			c.logger.Error("no ID Token Found")
		} else {

			// validate signature agains the JWK
			idToken, err = verifier.Verify(ctx, idTokenRaw)
			if err != nil {
				c.logger.Error("ID Token validation failed", "err", err)
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// retreive the nonce cookie
			nonceCookie, err := r.Cookie("nonce")
			if err != nil {
				c.logger.Error("Nonce cookie Not found", "err", err)
				http.Error(w, "nonce not found", http.StatusBadRequest)
				return
			}

			if idToken.Nonce != nonceCookie.Value {
				c.logger.Error("ID Token nonce does not match", "idToken.Nonce", idToken.Nonce, "Cookie.Nonce", nonceCookie.Value)
				http.Error(w, "nonce did not match", http.StatusBadRequest)
				return
			}
		}

		// Fetch Userinfo
		// NOTE: this will detects based on the Content-Type if the userinfo is application/jwt
		//       and if it is JWT it will validate signature agains JWK for the provider
		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Prints Retrieved information and  generate JSON HTTP response

		// Create global HTTP response object
		resp := struct {
			OAuth2Token     *oauth2.Token
			AccessTokenResp *JSONAccessTokenResponse
			IDTokenClaims   *json.RawMessage
			UserInfo        *oidc.UserInfo
			UserInfoClaims  *json.RawMessage
		}{oauth2Token, accessTokenResponse, new(json.RawMessage), userInfo, new(json.RawMessage)}

		// format id Token Claims
		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			c.logger.Error("Error Parsing ID Token Claims", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// format userinfo Claims
		if err := userInfo.Claims(&resp.UserInfoClaims); err != nil {
			c.logger.Error("Error Parsing USerinfo Claims", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Print ID Token Claims, and User Info
		idTokenClaims, err := json.MarshalIndent(resp.IDTokenClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}
		userinfoClaims, err := json.MarshalIndent(resp.UserInfoClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}

		c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaims))
		c.logger.Info("Userinfo Claims", "UserInfoClaims", string(userinfoClaims))

		// Format in JSON global HTTP response
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// send the global http response
		w.Write(data)

		// stop program
		go func() {
			c.logger.Info("Stopping server")
			os.Exit(0)
		}()
	})

	c.logger.Info("Go to http://127.0.0.1:5556/login")
	err = http.ListenAndServe("127.0.0.1:5556", nil)
	c.logger.Error("Error", "err", err)

	return nil

}
