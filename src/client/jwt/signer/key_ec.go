package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
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

	cert, err := k.genX509Cert()
	if err != nil {
		return nil, err
	}

	fingerprint := sha1.Sum(cert.Raw)

	// TODO: support mutli signing alg
	sig := jose.JSONWebKey{
		Use: "sig",
		// Algorithm:                 k.alg,
		Key:                       k.PublicKey,
		KeyID:                     k.Kid,
		Certificates:              []*x509.Certificate{cert},
		CertificateThumbprintSHA1: fingerprint[:],
	}

	enc := jose.JSONWebKey{
		Use: "enc",

		Key:                       k.PublicKey,
		KeyID:                     k.Kid,
		Certificates:              []*x509.Certificate{cert},
		CertificateThumbprintSHA1: fingerprint[:],
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{sig, enc},
	}

	return json.Marshal(jwks)
}

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *ECJWTSigner) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(k.signingMethod, claims)

	token.Header["kid"] = k.Kid

	return token.SignedString(k.PrivateKey)
}
func (k *ECJWTSigner) DecryptJWT(encryptedJwt, alg string) (string, error) {
	// return "", fmt.Errorf("unsupported encryption alg %s", alg)

	var method jwa.KeyAlgorithm

	switch alg {
	case "ECDH-ES":
		method = jwa.ECDH_ES
	case "ECDH-ES+A128KW":
		method = jwa.ECDH_ES_A128KW
	case "ECDH-ES+A192KW":
		method = jwa.ECDH_ES_A192KW
	case "ECDH-ES+A256KW":
		method = jwa.ECDH_ES_A256KW

	default:
		return "", fmt.Errorf("unsupported encryption alg %s", alg)
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedJwt), jwe.WithKey(method, k.PrivateKey))
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (k *ECJWTSigner) genX509Cert() (*x509.Certificate, error) {
	serialNumber := big.NewInt(100000000000000000)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "oidc-client-demo",
		},
		Issuer: pkix.Name{
			CommonName: "oidc-client-demo",
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		PublicKeyAlgorithm: x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, k.PublicKey, k.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
