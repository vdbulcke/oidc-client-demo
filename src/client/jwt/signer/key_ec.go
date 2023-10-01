package signer

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

type ECJWTSigner struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Kid        string

	alg           string
	signingMethod jwt.SigningMethod
}

func NewECJWTSigner(k *ecdsa.PrivateKey, alg, mockKid string) (*ECJWTSigner, error) {
	var method jwt.SigningMethod
	switch alg {
	case "ES256":
		method = jwt.SigningMethodES256
	case "ES384":
		method = jwt.SigningMethodES384
	case "ES512":
		method = jwt.SigningMethodES512
	default:
		return nil, fmt.Errorf("unsuported signing alg %s for EC Private key", alg)

	}

	rsaKid := mockKid
	if rsaKid == "" {
		var err error
		rsaKid, err = kid(&k.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	return &ECJWTSigner{
		PrivateKey:    k,
		PublicKey:     &k.PublicKey,
		Kid:           rsaKid,
		alg:           alg,
		signingMethod: method,
	}, nil

}

// JWKS is the JSON JWKS representation of the rsa.PublicKey
func (k *ECJWTSigner) JWKS() ([]byte, error) {

	// TODO: support mutli signing alg
	jwk := jose.JSONWebKey{
		Use:       "sig",
		Algorithm: k.alg,
		Key:       k.PublicKey,
		KeyID:     k.Kid,
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	return json.Marshal(jwks)
}

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *ECJWTSigner) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(k.signingMethod, claims)

	token.Header["kid"] = k.Kid

	return token.SignedString(k.PrivateKey)
}
