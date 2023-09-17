package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
)

// kid generates a kid by sha256 sum public key
func kid(k crypto.PublicKey) (string, error) {

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(publicKeyDERBytes); err != nil {
		return "", err
	}
	publicKeyDERHash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(publicKeyDERHash), nil
}
