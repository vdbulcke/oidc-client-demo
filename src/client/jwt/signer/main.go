package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ParsePrivateKey pase PEM private key file, and returns
// a crypto.PrivateKey interface.
func ParsePrivateKey(filename string) (crypto.PrivateKey, error) {

	// read private key file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	key, _ := pem.Decode(data)
	if key == nil {
		return nil, fmt.Errorf("error decoding PEM file, invalid format")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(key.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(key.Bytes)
		if err != nil {
			privKey, err = x509.ParseECPrivateKey(key.Bytes)
			if err != nil {
				return nil, err
			}
		}
	}

	return privKey, nil
}

// NewJwtSigner create a JwtSigned for the correspond key type
//
// supported key tupes are rsa.PrivateKey and ecdsa.PrivateKey
func NewJwtSigner(key crypto.PrivateKey, alg, mockKid string) (JwtSigner, error) {

	// case key to derive hc vault key type
	switch priv := key.(type) {
	case *rsa.PrivateKey:

		return NewRSAJWTSigner(priv, alg, mockKid)

	case *ecdsa.PrivateKey:

		return NewECJWTSigner(priv, alg, mockKid)
	default:
		return nil, errors.New("unsupported key type. Must be one of RSA or EC")
	}

}
