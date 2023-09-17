package oidcclient

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtProfileClaims struct {
	Jti string `json:"jti,omitempty"`
	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`
	jwt.RegisteredClaims
}

// https://www.rfc-editor.org/rfc/rfc7523.html
func (c *OIDCClient) GenerateJwtProfile(endpoint string) (string, error) {
	if c.jwtsigner == nil {
		return "", errors.New("jwtsigner is required for jwt profile")
	}

	jti, err := c.randString(10)
	if err != nil {
		return "", err
	}

	// override audiance if config present
	if c.config.JwtProfileAudiance != "" {
		endpoint = c.config.JwtProfileAudiance
	}

	claims := JwtProfileClaims{
		Jti:      jti,
		Audience: endpoint,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(c.config.JwtProfileTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    c.config.ClientID,
			Subject:   c.config.ClientID,
			// ID:        "1",
			// Audience: []string{endpoint},
		},
	}

	signedJwt, err := c.jwtsigner.SignJWT(claims)
	if err != nil {
		return "", err
	}

	return signedJwt, nil
}

func (c *OIDCClient) GenerateRequestJwt(extraClaims map[string]interface{}) (string, error) {
	if c.jwtsigner == nil {
		return "", errors.New("jwtsigner is required for request jwt ")
	}

	aud := c.config.Issuer

	// override audiance if config present
	if c.config.JwtRequestAudiance != "" {
		aud = c.config.JwtRequestAudiance
	}

	claims := jwt.MapClaims{}
	// standard claims
	claims["aud"] = aud
	claims["exp"] = jwt.NewNumericDate(time.Now().Add(c.config.JwtRequestTokenDuration))
	claims["iat"] = jwt.NewNumericDate(time.Now())
	claims["nbf"] = jwt.NewNumericDate(time.Now())
	claims["iss"] = c.config.ClientID
	claims["sub"] = c.config.ClientID
	// signed params
	claims["client_id"] = c.config.ClientID
	claims["redirect_uri"] = c.config.RedirectUri
	claims["scope"] = strings.Join(c.config.Scopes, " ")
	claims["response_type"] = "code"

	if c.config.AcrValues != "" {
		claims["acr_values"] = c.config.AcrValues
	}

	// add extra claims to request jwt
	for k, v := range extraClaims {
		claims[k] = v
	}

	if c.config.JwtRequestAdditionalParameter != nil {

		// add extra claims to request jwt
		for k, v := range c.config.JwtRequestAdditionalParameter {
			claims[k] = v
		}
	}

	// response_type
	signedJwt, err := c.jwtsigner.SignJWT(claims)
	if err != nil {
		c.logger.Error("error signing", err)
		return "", err
	}

	return signedJwt, nil
}
