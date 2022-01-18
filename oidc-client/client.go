package oidcclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
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

func (c *OIDCClient) validateAMR(idToken *oidc.IDToken) bool {

	c.logger.Debug("Starting AMR validation")

	// check if need to validate amr values
	if len(c.config.AMRWhitelist) == 0 {
		return true
	}

	// parse amr claims
	var claims struct {
		Amr []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		c.logger.Error("Error parsing amr claims", "id_token", idToken, "err", err)
		return false
	}

	// check if at least one of the whitelisted
	// amr is in the claims
	for _, amr := range c.config.AMRWhitelist {
		if stringInSlice(amr, claims.Amr) {
			return true
		}
	}

	return false

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

// RefreshTokenFlow renew the refresh token
//
// ref: https://github.com/nonbeing/awsconsoleauth/blob/master/http.go#L46
func (c *OIDCClient) RefreshTokenFlow(refreshToken string, skipUserinfo bool, skipIdTokenVerification bool) error {

	token := new(oauth2.Token)
	token.RefreshToken = refreshToken
	token.Expiry = time.Now()

	// TokenSource will refresh the token if needed (which is likely in this
	// use case)
	ts := c.oAuthConfig.TokenSource(context.TODO(), token)

	// get the oauth Token
	oauth2Token, err := ts.Token()
	if err != nil {
		c.logger.Error("Failed to Renew Access Token from refresh token", "refresh-token", refreshToken, "error", err)
		return err
	}

	// Parse Access Token
	accessTokenResponse, err := c.parseAccessTokenResponse(oauth2Token)
	if err != nil {
		c.logger.Error("Error Parsing Access Token", "err", err)
		return err
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
	} else if !skipIdTokenVerification {

		// validate signature agains the JWK
		idToken, err = c.verifier.Verify(c.ctx, idTokenRaw)
		if err != nil {
			c.logger.Error("ID Token validation failed", "err", err)

			return err
		}

		// validate AMR Values
		if !c.validateAMR(idToken) {
			c.logger.Error("Amr not valid", "amrs", c.config.AMRWhitelist)
		}

		// Print IDToken
		var idTokenClaims *json.RawMessage

		// format id Token Claims
		if err := idToken.Claims(&idTokenClaims); err != nil {
			c.logger.Error("Error Parsing ID Token Claims", "err", err)
			return err
		}

		// Print ID Token Claims, and User Info
		idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}
		c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaimsByte))
	}

	// Fetch Userinfo
	if !skipUserinfo {
		// NOTE: this will detects based on the Content-Type if the userinfo is application/jwt
		//       and if it is JWT it will validate signature agains JWK for the provider
		userInfo, err := c.provider.UserInfo(c.ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			return err
		}

		var userInfoClaims *json.RawMessage
		// format userinfo Claims
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			c.logger.Error("Error Parsing USerinfo Claims", "err", err)
			return err
		}

		userInfoClaimsByte, err := json.MarshalIndent(userInfoClaims, "", "    ")
		if err != nil {
			c.logger.Error("Could not parse idTokenClaims", "err", err)
		}

		c.logger.Info("Userinfo Claims", "UserInfoClaims", string(userInfoClaimsByte))

	}

	return nil

}

// OIDCAuthorizationCodeFlow starts a HTTP server and
// set handler for performing the Authorization code flow
func (c *OIDCClient) OIDCAuthorizationCodeFlow() error {

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

	mux := http.DefaultServeMux

	// http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// setting nonce and state as cookies
		// that will be validate against callback response
		c.setCallbackCookie(w, r, "state", state)
		c.setCallbackCookie(w, r, "nonce", nonce)

		// authorize URL
		var authorizeURL string

		// setting Authorize call options (&nonce=...)
		authNonceOption := oauth2.SetAuthURLParam("nonce", nonce)

		// if need acr_values
		if c.config.AcrValues != "" {
			// setting Authorize call options (&acr_values=...)
			acrValuesOption := oauth2.SetAuthURLParam("acr_values", c.config.AcrValues)

			// add &state=... and &nonce=...&acr_values=... to authorize request url
			authorizeURL = c.oAuthConfig.AuthCodeURL(state, authNonceOption, acrValuesOption)
		} else {
			// add &state=... and &nonce=... to authorize request url
			authorizeURL = c.oAuthConfig.AuthCodeURL(state, authNonceOption)
		}

		// redirect to authorization URL
		http.Redirect(w, r, authorizeURL, http.StatusFound)
	})

	// http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		// read back the state cookie
		stateCookie, err := r.Cookie("state")
		if err != nil {
			c.logger.Error("state not found", "err", err)
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		// validate against callback state query_string param
		if r.URL.Query().Get("state") != stateCookie.Value {
			c.logger.Error("state did not match", "cookie_state", stateCookie.Value, "query_state", r.URL.Query().Get("state"))
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		// get authZ code
		authZCode := r.URL.Query().Get("code")
		c.logger.Info("Received AuthZ Code", "code", authZCode)

		// Access Token Response
		oauth2Token, err := c.oAuthConfig.Exchange(c.ctx, authZCode)
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
			idToken, err = c.verifier.Verify(c.ctx, idTokenRaw)
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

			// validate AMR Values
			if !c.validateAMR(idToken) {
				c.logger.Error("Amr not valid", "amrs", c.config.AMRWhitelist)
			}
		}

		// Fetch Userinfo
		// NOTE: this will detects based on the Content-Type if the userinfo is application/jwt
		//       and if it is JWT it will validate signature agains JWK for the provider
		userInfo, err := c.provider.UserInfo(c.ctx, oauth2.StaticTokenSource(oauth2Token))
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
		//nolint
		w.Write(data)

		// stop program
		go func() {
			c.logger.Info("Stopping server")
			os.Exit(0)
		}()
	})

	localAddress := fmt.Sprintf("%s:%d", c.config.ListenAddress, c.config.ListenPort)
	c.logger.Info(fmt.Sprintf("Go to http://%s:%d/login", c.config.ListenAddress, c.config.ListenPort))
	// create a new server
	httpServer := http.Server{
		Addr:     localAddress,                                            // configure the bind address
		Handler:  mux,                                                     // set the default handler
		ErrorLog: c.logger.StandardLogger(&hclog.StandardLoggerOptions{}), // set the logger for the server
		// ReadTimeout:  5 * time.Second,                                          // max time to read request from the client
		// WriteTimeout: 10 * time.Second,                                         // max time to write response to the client
		// IdleTimeout:  120 * time.Second,                                        // max time for connections using TCP Keep-Alive
	}

	// start the server
	go func() {

		err := httpServer.ListenAndServe()
		if err != nil {
			if err == http.ErrServerClosed {
				c.logger.Info("Server is shuting down", "error", err)
				os.Exit(0)
			}
			c.logger.Error("Error starting server", "error", err)
			os.Exit(1)
		}
	}()

	// trap sigterm or interupt and gracefully shutdown the server
	close := make(chan os.Signal, 1)
	signal.Notify(close, os.Interrupt)
	// signal.Notify(c, os.Kill)

	// Block until a signal is received.
	sig := <-close
	c.logger.Info("Got signal", "sig", sig)

	// gracefully shutdown the server, waiting max 30 seconds for current operations to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() {
		// extra handling here
		cancel()
	}()

	err = httpServer.Shutdown(ctx)
	if err != nil {
		c.logger.Error("failure while shutting down server", "error", err)
	}

	return nil

}
