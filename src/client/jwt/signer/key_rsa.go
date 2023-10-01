package signer

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

type RSAJWTSigner struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string

	alg           string
	signingMethod jwt.SigningMethod
}

func NewRSAJWTSigner(k *rsa.PrivateKey, alg, mockKid string) (*RSAJWTSigner, error) {
	var method jwt.SigningMethod
	switch alg {
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512
	default:
		return nil, fmt.Errorf("unsuported signing alg %s for RSA private key ", alg)

	}
	rsaKid := mockKid
	if rsaKid == "" {
		var err error
		rsaKid, err = kid(&k.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	return &RSAJWTSigner{
		PrivateKey:    k,
		PublicKey:     &k.PublicKey,
		Kid:           rsaKid,
		alg:           alg,
		signingMethod: method,
	}, nil

}

// JWKS is the JSON JWKS representation of the rsa.PublicKey
func (k *RSAJWTSigner) JWKS() ([]byte, error) {

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
func (k *RSAJWTSigner) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(k.signingMethod, claims)

	token.Header["kid"] = k.Kid

	return token.SignedString(k.PrivateKey)
}
