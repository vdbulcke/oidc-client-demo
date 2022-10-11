package oidcclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

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

func (c *OIDCClient) processAccessTokenResponse(accessTokenResponse *JSONAccessTokenResponse) {

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
