package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/vdbulcke/oauthx"
)

// OIDCAuthorizationCodeFlow starts a HTTP server and
// set handler for performing the Authorization code flow
func (c *OIDCClient) OIDCAuthorizationCodeFlow() error {

	// trap sigterm or interupt and gracefully shutdown the server
	close := make(chan os.Signal, 1)
	signal.Notify(close, os.Interrupt)
	// signal.Notify(c, os.Kill)
	mux := http.DefaultServeMux

	// create cache of mapping state to associated oauth context
	cache := make(map[string]*oauthx.OAuthContext)

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		stateOpt := oauthx.StateOpt()
		nonceOpt := oauthx.NonceOpt()
		pkceOpt := oauthx.PKCEOpt()
		if c.config.MockNonce != "" {
			nonceOpt = oauthx.SetNonceOpt(c.config.MockNonce)
		}
		if c.config.MockState != "" {
			stateOpt = oauthx.SetStateOpt(c.config.MockState)
		}

		if c.config.MockCodeVerifier != "" {
			pkceOpt = oauthx.PKCES256ChallengeOpt(c.config.MockCodeVerifier)
		}

		// NewBaseAuthzRequest create a new base AuthZRequest with
		// resonable default:
		//   - nonce
		//   - state
		//   - response_type=code
		//   - pkce S256
		authzReq := oauthx.NewAuthZRequest(
			// response_type
			//    REQUIRED.  OAuth 2.0 Response Type value that determines the
			//    authorization processing flow to be used, including what
			//    parameters are returned from the endpoints used.  When using the
			//    Authorization Code Flow, this value is "code".
			oauthx.ResponseTypeCodeOpt(),
			// state
			//    RECOMMENDED.  Opaque value used to maintain state between the
			//    request and the callback.  Typically, Cross-Site Request Forgery
			//    (CSRF, XSRF) mitigation is done by cryptographically binding the
			//    value of this parameter with a browser cookie.
			stateOpt,
			// nonce
			//    OPTIONAL.  String value used to associate a Client session with an
			//    ID Token, and to mitigate replay attacks.  The value is passed
			//    through unmodified from the Authentication Request to the ID
			//    Token.  Sufficient entropy MUST be present in the "nonce" values
			//    used to prevent attackers from guessing values.  For
			//    implementation notes, see Section 15.5.2.
			nonceOpt,

			oauthx.ClientIdOpt(c.config.ClientID),
			oauthx.RedirectUriOpt(c.config.RedirectUri),
		)

		if len(c.config.Scopes) > 0 {
			authzReq.AddOpts(
				oauthx.ScopeOpt(c.config.Scopes...),
			)
		}

		if c.config.AcrValues != "" {
			authzReq.AddOpts(
				oauthx.AcrValuesOpt(strings.Split(c.config.AcrValues, " ")),
			)
		}

		if c.config.ParseClaims != nil {

			authzReq.AddOpts(
				oauthx.ClaimsParameterOpt(c.config.ParseClaims),
			)
		}

		if len(c.config.AuthorizationDetails) > 0 {

			c.logger.Debug("auth details", "val", c.config.AuthorizationDetails)
			authzReq.AddOpts(
				oauthx.AuthorizationDetailsParamaterOpt(c.config.AuthorizationDetails),
			)
		}

		if c.config.UsePKCE {
			authzReq.AddOpts(
				// rfc7636
				// Request Context:
				// code_verifier => generated
				//    REQUIRED.  Code verifier
				//
				// Request params:
				// code_challenge => Generated
				//    REQUIRED.  Code challenge.

				// code_challenge_method => "S256"
				//    OPTIONAL, defaults to "plain" if not present in the request.  Code
				//    verifier transformation method is "S256" or "plain".
				pkceOpt,
			)
		}

		if c.config.UsePAR {
			authzReq.AddOpts(
				// sends authorization request options via
				// pushed authorization endpoint and
				// only use client_id and request_uri for
				// redirect to the authorization_endpoint
				oauthx.WithPushedAuthorizationRequest(),
			)

			for k, v := range c.config.PARAdditionalParameter {
				// Set each key/value as extra parameter on the pushed
				// authorization request as well as claims if use
				// with oauthx.WithGeneratedRequestJWT() option
				authzReq.AddOpts(
					oauthx.SetOAuthParam(k, v),
				)
			}

		}

		if c.config.LegacyRequestJwtHeaderType {
			authzReq.AddOpts(
				// force JWT header 'typ': 'JWT'
				oauthx.WithLegacyRequestJWTHeaderType(),
			)
		}

		if c.config.UseRequestParameter {

			authzReq.AddOpts(
				// generate the 'request' jwt paramater by
				// adding authorization options as jwt claims
				// oauthx.WithGeneratedRequestJWT(),
				oauthx.WithGeneratedRequestJWTOnly(),
			)

			for k, v := range c.config.JwtRequestAdditionalParameter {
				// add extra key value claims to 'request' jwt
				authzReq.AddOpts(
					oauthx.SetOAuthClaimOnly(k, v),
				)
			}
		}

		if c.config.StrictOIDCAndRCF6749Param {
			authzReq.AddOpts(

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

				oauthx.WithStrictRequiredAuthorizationParams(),
			)
		}

		// perform the AUthotization request (with PAR is configured)
		authorization, err := c.client.DoAuthorizationRequest(c.ctx, authzReq)
		if err != nil {
			c.logger.Error("Failed to make PAR request", "err", err)

			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}

			http.Error(w, "Failed to make PAR request: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// authorize URL
		authorizeURL := authorization.Url

		params := url.Values{}

		// if specified add extra K/V parameter on authorize request
		if c.config.AuthorizeAdditionalParameter != nil {
			for k, v := range c.config.AuthorizeAdditionalParameter {

				params.Set(k, v)
			}
			authorizeURL = oauthx.PlumbingAddParamToEndpoint(authorizeURL, params)
		}

		// redirect to authorization URL
		cache[authorization.ReqCtx.State] = authorization.ReqCtx
		// setting nonce and state as cookies

		// that will be validate against callback response
		c.setCallbackCookie(w, r, "state", authorization.ReqCtx.State)
		c.setCallbackCookie(w, r, "nonce", authorization.ReqCtx.Nonce)

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
		state := r.URL.Query().Get("state")
		if state != stateCookie.Value {
			c.logger.Error("state did not match", "cookie_state", stateCookie.Value, "query_state", r.URL.Query().Get("state"))
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		// find the oauth request context from the state parameter
		oauthCtx, ok := cache[state]
		if !ok {
			c.logger.Error("could not find oauth context based on state", "cookie_state", stateCookie.Value, "query_state", r.URL.Query().Get("state"))
			http.Error(w, "could not find oauth context based on state", http.StatusBadRequest)
			return

		}

		// clear cache
		delete(cache, state)

		// get authZ code
		authZCode := r.URL.Query().Get("code")
		c.logger.Info("Received AuthZ Code", "code", authZCode)
		if authZCode == "" {
			c.logger.Error("could not find 'code'")
			http.Error(w, "could not find 'code'", http.StatusBadRequest)
			return
		}

		// generate the token endpoint request based on the authorization code
		// and the oauth context
		tokenRequest := oauthx.NewAuthorizationCodeGrantTokenRequest(authZCode, oauthCtx)

		if c.config.FakePKCEVerifier {
			tokenRequest.AddOpts(
				// if fake-pkce-verifier flags is set
				// replace the codeVerifier by a dummy value
				// to see how the Authorization Server handle the request
				oauthx.PKCEVerifierOpt("dummy"),
			)
		}

		tokenResp, err := c.client.DoTokenRequest(c.ctx, tokenRequest)
		if err != nil {
			c.logger.Error("Failed to get Access Token", "err", err)

			var httpErr *oauthx.HttpErr
			if errors.As(err, &httpErr) {
				c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
			}

			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Print Access Token
		c.processAccessTokenResponse(tokenResp)

		if tokenResp.IDToken != "" {

			idToken, err := c.client.ParseIDToken(c.ctx, tokenResp.IDToken)
			if err != nil {
				c.logger.Error("ID Token standard validation failed", "err", err)
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// extra id_token validation
			opts := []oauthx.IDTokenValidationFunc{
				oauthx.WithIDTokenNonceValidation(oauthCtx.Nonce),
			}
			if len(c.config.ACRWhitelist) > 0 {
				opts = append(opts, oauthx.WithIDTokenAcrWhitelist(c.config.ACRWhitelist))
			}

			if len(c.config.AMRWhitelist) > 0 {
				//
				// Custom validation options
				//
				amrWhitelistValidationOpt := func(ctx context.Context, t *oauthx.IDToken) error {

					for _, amr := range c.config.AMRWhitelist {
						if slices.Contains(t.Amr, amr) {
							// if at least one amr from the whitelist
							// is present in the IDToken then success
							return nil
						}
					}
					return fmt.Errorf("id_token: no matching amr whitelist '%s' in token '%s'",
						strings.Join(c.config.AMRWhitelist, ","),
						strings.Join(t.Amr, ","))
				}
				opts = append(opts, amrWhitelistValidationOpt)
			}

			err = idToken.Validate(c.ctx, opts...)
			if err != nil {
				c.logger.Error("ID Token extra validation failed", "err", err)
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// print idToken
			c.processIdToken(idToken)

			// Save sub from ID Token into context
			// for Userinfo validation
			sub := idToken.Subject
			k := subCtxKey("sub")
			c.ctx = context.WithValue(c.ctx, k, sub)
		}

		if c.config.AccessTokenJwt {
			// try to parse access token as JWT
			accessTokenRaw := tokenResp.AccessToken
			if accessTokenRaw == "" {
				c.logger.Error("no Access Token Found")
			} else {
				// validate signature against the JWK
				err := c.processAccessToken(c.ctx, accessTokenRaw)
				if err != nil {
					c.logger.Error("Access Token validation failed", "err", err)
					http.Error(w, "Failed to verify Access Token: "+err.Error(), http.StatusInternalServerError)
					return
				}

			}
		}

		if c.config.RefreshTokenJwt {
			// try to parse refresh token as JWT
			refreshTokenRaw := tokenResp.RefreshToken
			if refreshTokenRaw == "" {
				c.logger.Error("no Refresh Token Found")
			} else {
				// validate signature against the JWK
				err := c.processRefreshToken(c.ctx, refreshTokenRaw)
				if err != nil {
					c.logger.Error("Refresh Token validation failed", "err", err)
					http.Error(w, "Failed to verify Refresh Token: "+err.Error(), http.StatusInternalServerError)
					return
				}

			}
		}

		// Fetch Userinfo
		if !c.config.SkipUserinfo {
			userinfo, err := c.client.DoUserinfoRequest(c.ctx, tokenResp.AccessToken)
			if err != nil {
				http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
				var httpErr *oauthx.HttpErr
				if errors.As(err, &httpErr) {
					c.logger.Error("http error", "response_headers", httpErr.ResponseHeader, "response_body", string(httpErr.RespBody))
				}
				return
			}

			_ = c.userinfo(userinfo)

			// validation 'sub'
			// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
			sub := userinfo.Sub
			if sub == "" {
				c.logger.Error("Missing mandatory 'sub' field")
			}

			// fetch id_token 'sub' from context
			k := subCtxKey("sub")
			idTokenSub := c.ctx.Value(k)
			if idTokenSub != nil {

				// userinfo 'sub' must match id_token 'sub'
				if sub != idTokenSub.(string) {
					c.logger.Error("'sub' fields do not match", "idTokenSub", idTokenSub, "userinfoSub", sub)
				}

			} else {
				c.logger.Error("Could not retrieve id_token 'sub' field from context")
			}
		}

		// Create global HTTP response object

		// Format in JSON global HTTP response
		data, err := json.MarshalIndent(tokenResp.Raw, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// send the global http response
		//nolint
		w.Write(data)

		if !c.config.KeepRunning {
			// stop program
			go func() {
				c.logger.Info("Stopping server")
				close <- os.Interrupt
			}()
		}
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

	err := httpServer.Shutdown(ctx)
	if err != nil {
		c.logger.Error("failure while shutting down server", "error", err)
	}

	return nil

}
