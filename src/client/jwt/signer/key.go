package signer

import (
	"github.com/golang-jwt/jwt/v5"
)

// JwtSigner interface for signing jwt
// and generating jwks
type JwtSigner interface {
	JWKS() ([]byte, error)                     // marshal of JWKS
	SignJWT(claims jwt.Claims) (string, error) // signs jwt claims
}
