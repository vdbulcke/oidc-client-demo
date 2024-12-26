package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
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
