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

		// Access Token
		oauth2Token, err := oAuthConfig.Exchange(ctx, authZCode)
		if err != nil {
			c.logger.Error("Failed to get Access Token", "err", err)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// c.logger.Info("Received Access Token Response", "oauth2Token", oauth2Token)
		c.logger.Info("Received Access Token", "AccessToken", oauth2Token.AccessToken)

		// Parsing Token
		c.logger.Info("Received Access Token Response", "token_type", oauth2Token.Type())
		c.logger.Info("Received Access Token Response", "expires_in", oauth2Token.Expiry.String())

		respIdToken, ok := oauth2Token.Extra("id_token").(string)
		if ok {
			c.logger.Info("Received Access Token Response", "id_token", respIdToken)
		}

		respRefreshToken, ok := oauth2Token.Extra("refresh_token").(string)
		if ok {
			c.logger.Info("Received Access Token Response", "refresh_token", respRefreshToken)
		}

		respNonce, ok := oauth2Token.Extra("nonce").(string)
		if ok {
			c.logger.Info("Received Access Token Response", "nonce", respNonce)
		}

		respScope, ok := oauth2Token.Extra("scope").(string)
		if ok {
			c.logger.Info("Received Access Token Response", "scope", respScope)
		}

		// ID Token
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			c.logger.Error("Could not parse id_token")
		}
		c.logger.Info("Parsed ID Token ", "IDToken", rawIDToken)

		nonce, err := r.Cookie("nonce")
		if err != nil {
			c.logger.Error("Nonce cookie Not found", "err", err)
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			c.logger.Error("ID Token validation failed", "err", err)
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if idToken.Nonce != nonce.Value {
			c.logger.Error("ID Token nonce does not match", "idToken.Nonce", idToken.Nonce, "Cookie.Nonce", nonce.Value)
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}
		// Userinfo

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token    *oauth2.Token
			IDTokenClaims  *json.RawMessage
			UserInfo       *oidc.UserInfo
			UserInfoClaims *json.RawMessage
		}{oauth2Token, new(json.RawMessage), userInfo, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			c.logger.Error("Error Parsing ID Token Claims", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := userInfo.Claims(&resp.UserInfoClaims); err != nil {
			c.logger.Error("Error Parsing USerinfo Claims", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

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

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)

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
