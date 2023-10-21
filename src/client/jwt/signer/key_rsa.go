package signer

import (
	"crypto/rand"
	"crypto/rsa"
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
func (k *RSAJWTSigner) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(k.signingMethod, claims)

	token.Header["kid"] = k.Kid

	return token.SignedString(k.PrivateKey)
}

// DecryptJWT decrypt jwt
func (k *RSAJWTSigner) DecryptJWT(encryptedJwt, alg string) (string, error) {
	var method jwa.KeyAlgorithm

	switch alg {
	case "RSA-OAEP-256":
		method = jwa.RSA_OAEP_256

	case "RSA-OAEP":
		method = jwa.RSA_OAEP
	default:
		return "", fmt.Errorf("unsupported encryption alg %s", alg)
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedJwt), jwe.WithKey(method, k.PrivateKey))
	if err != nil {
		return "", err
	}

	return string(decrypted), nil

}

func (k *RSAJWTSigner) genX509Cert() (*x509.Certificate, error) {
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
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA512WithRSA,
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
