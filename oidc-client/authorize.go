package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/hashicorp/go-hclog"
	pkce "github.com/vdbulcke/oidc-client-demo/oidc-client/internal/pkce"
	"golang.org/x/oauth2"
)

// OIDCAuthorizationCodeFlow starts a HTTP server and
// set handler for performing the Authorization code flow
func (c *OIDCClient) OIDCAuthorizationCodeFlow() error {

	// trap sigterm or interupt and gracefully shutdown the server
	close := make(chan os.Signal, 1)
	signal.Notify(close, os.Interrupt)
	// signal.Notify(c, os.Kill)

	// generate state and none
	state, err := c.NewState(6)
	if err != nil {
		c.logger.Error("Could not generate state", "err", err)
		return err
	}

	nonce, err := c.NewNonce(6)
	if err != nil {
		c.logger.Error("Could not generate nonce", "err", err)
		return err
	}

	// pkce flow
	var codeVerifier, challenge string
	if c.config.UsePKCE {

		// generate new code
		codeVerifier, err = c.NewCodeVerifier(c.config.PKCECodeLength)
		if err != nil {
			c.logger.Error("Fail to generate PKCE code", "error", err)
			return err
		}

		// generate challenge
		challenge, err = pkce.NewCodeChallenge(codeVerifier, c.config.PKCEChallengeMethod)
		if err != nil {
			c.logger.Error("Fail to generate PKCE Challenge", "code", codeVerifier, "error", err)
			return err
		}

	}

	var parResp *PARResponse
	if c.config.UsePAR {
		parResp, err = c.DoPARRequest(challenge, nonce, state)
		if err != nil {
			c.logger.Error("error doing PAR request", "error", err)
			return err
		}

		c.logger.Info("Received PAR Response", "request_uri", parResp.RequestUri, "expires_in", parResp.ExpiresIn)
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

		// Extra parameter for authorize endpoint
		var authorizeOpts []oauth2.AuthCodeOption

		// if using PAR
		// not need for the extra parameter parameters
		if c.config.UsePAR {

			url, err := url.Parse(c.oAuthConfig.Endpoint.AuthURL)
			if err != nil {
				c.logger.Error("error parsing Authorize url", "error", err)
			}

			q := url.Query()
			q.Add("request_uri", parResp.RequestUri)
			q.Add("client_id", c.config.ClientID)

			// if specified add extra K/V parameter on authorize request
			if c.config.AuthorizeAdditionalParameter != nil {
				for k, v := range c.config.AuthorizeAdditionalParameter {
					q.Add(k, v)
				}
			}

			url.RawQuery = q.Encode()

			authorizeURL = url.String()
			c.logger.Debug("auth URL", "url", authorizeURL)

		} else {
			// setting Authorize call options (&nonce=...)
			authNonceOption := oauth2.SetAuthURLParam("nonce", nonce)
			authorizeOpts = append(authorizeOpts, authNonceOption)

			// if need acr_values
			if c.config.AcrValues != "" {
				// setting Authorize call options (&acr_values=...)
				acrValuesOption := oauth2.SetAuthURLParam("acr_values", c.config.AcrValues)
				authorizeOpts = append(authorizeOpts, acrValuesOption)
			}

			// handle pkce paramater
			if c.config.UsePKCE {

				pkceOption := oauth2.SetAuthURLParam("code_challenge", challenge)
				authorizeOpts = append(authorizeOpts, pkceOption)

				pkceMethodOption := oauth2.SetAuthURLParam("code_challenge_method", c.config.PKCEChallengeMethod)
				authorizeOpts = append(authorizeOpts, pkceMethodOption)

			}

			// if specified add extra K/V parameter on authorize request
			if c.config.AuthorizeAdditionalParameter != nil {
				for k, v := range c.config.AuthorizeAdditionalParameter {

					authorizeOpts = append(authorizeOpts, oauth2.SetAuthURLParam(k, v))
				}
			}

			// generate the authorize url with the extra options
			authorizeURL = c.oAuthConfig.AuthCodeURL(state, authorizeOpts...)

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
		var oauth2Token *oauth2.Token
		if c.config.UsePKCE {

			// if fake-pkce-verifier flags is set
			// replace the codeVerifier by a dummy value
			// to see how the Authorization Server handle the request
			if c.config.FakePKCEVerifier {
				codeVerifier = "dummy"
			}

			// set extra pkce param
			pkceVerifierOption := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

			c.logger.Debug("using pkce code_verifier for getting access token")

			oauth2Token, err = c.oAuthConfig.Exchange(c.ctx, authZCode, pkceVerifierOption)
			if err != nil {
				c.logger.Error("Failed to get Access Token", "err", err)
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {

			// without pkce
			oauth2Token, err = c.oAuthConfig.Exchange(c.ctx, authZCode)
			if err != nil {
				c.logger.Error("Failed to get Access Token", "err", err)
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				return
			}
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
		if c.config.OutputEnabled {
			err = c.writeOutput(accessTokenResponseLog, c.config.AccessTokenRespFile)
			if err != nil {
				c.logger.Error("Error Writing Access Token Response file", "error", err)
			}
		}

		// Validate ID Token
		idTokenRaw := accessTokenResponse.IDToken
		if idTokenRaw == "" {
			c.logger.Error("no ID Token Found")
		} else {

			// validate signature agains the JWK
			idToken, err := c.processIdToken(idTokenRaw)
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

		if c.config.AccessTokenJwt {
			// try to parse access token as JWT
			accessTokenRaw := accessTokenResponse.AccessToken
			if accessTokenRaw == "" {
				c.logger.Error("no Access Token Found")
			} else {
				// validate signature against the JWK
				_, err := c.processAccessToken(c.ctx, accessTokenRaw)
				if err != nil {
					c.logger.Error("Access Token validation failed", "err", err)
					http.Error(w, "Failed to verify Access Token: "+err.Error(), http.StatusInternalServerError)
					return
				}

			}
		}

		if c.config.RefreshTokenJwt {
			// try to parse refresh token as JWT
			refreshTokenRaw := accessTokenResponse.RefreshToken
			if refreshTokenRaw == "" {
				c.logger.Error("no Refresh Token Found")
			} else {
				// validate signature against the JWK
				_, err := c.processRefreshToken(c.ctx, refreshTokenRaw)
				if err != nil {
					c.logger.Error("Refresh Token validation failed", "err", err)
					http.Error(w, "Failed to verify Refresh Token: "+err.Error(), http.StatusInternalServerError)
					return
				}

			}
		}

		// Fetch Userinfo
		err = c.userinfo(oauth2Token)
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Create global HTTP response object
		resp := struct {
			OAuth2Token     *oauth2.Token
			AccessTokenResp *JSONAccessTokenResponse
		}{oauth2Token, accessTokenResponse}

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
			close <- os.Interrupt
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
