package oidcclient

import (
	"context"
	"encoding/json"

	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

// processIdToken Handle idToken call
func (c *OIDCClient) processIdToken(idTokenRaw string) (*oidc.IDToken, error) {

	// parse header
	header, headerClaims, err := c.parseJWTHeader(idTokenRaw)
	if err != nil {
		c.logger.Error("error ID Token parsing header", "error", err)
	} else {
		// pretty print header
		c.logger.Info("IDToken header", "header", header)

		if algI, ok := headerClaims["alg"]; ok {

			// check string
			if alg, ok := algI.(string); ok {
				// ony supported encryption alg
				if slices.Contains(c.config.TokenEncryptionAlg, alg) {
					// if alg == "RSA-OAEP-256" || alg == "RSA-OAEP" || alg == "ECDH-ES" {
					jwtPayload, err := c.jwtsigner.DecryptJWT(idTokenRaw, alg)
					if err != nil {
						c.logger.Error("error decrypting jwt", "error", err)
					} else {

						// nested jwt payload
						idTokenRaw = jwtPayload
						c.logger.Info("Encryped JWT", "payload", jwtPayload)
						nestedHeader, _, err := c.parseJWTHeader(idTokenRaw)
						if err == nil {
							c.logger.Info("IDToken nested token header", "header", nestedHeader)
						}
					}
				}

			}

		}
	}

	// validate signature agains the JWK
	idToken, err := c.verifier.Verify(c.ctx, idTokenRaw)
	if err != nil {
		c.logger.Error("ID Token validation failed", "err", err)

		return nil, err
	}

	// validate AMR Values
	if !c.validateAMR(idToken) {
		c.logger.Error("Amr not valid", "amrs", c.config.AMRWhitelist)
	}

	// validate AMR Values
	if !c.validateACR(idToken) {
		c.logger.Error("Acr not valid", "ArcList", c.config.ACRWhitelist)
	}

	// Print IDToken
	var idTokenClaims *json.RawMessage

	// format id Token Claims
	if err := idToken.Claims(&idTokenClaims); err != nil {
		c.logger.Error("Error Parsing ID Token Claims", "err", err)
		return nil, err
	}

	// Print ID Token Claims
	idTokenClaimsByte, err := json.MarshalIndent(idTokenClaims, "", "    ")
	if err != nil {
		c.logger.Error("Could not parse idTokenClaims", "err", err)
	}
	c.logger.Info("IDToken Claims", "IDTokenClaims", string(idTokenClaimsByte))

	if c.config.OutputEnabled {
		err = c.writeOutput(idTokenClaimsByte, c.config.IDTokenFile)
		if err != nil {
			c.logger.Error("Error Writing IDToken file", "error", err)
		}
	}

	// Save sub from ID Token into context
	// for Userinfo validation
	sub := idToken.Subject
	k := subCtxKey("sub")
	c.ctx = context.WithValue(c.ctx, k, sub)

	return idToken, nil
}
