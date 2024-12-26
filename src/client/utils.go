package oidcclient

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
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

func (c *OIDCClient) parseJWTHeader(rawToken string) (string, map[string]interface{}, error) {

	parts := strings.Split(rawToken, ".")
	// header must be the first part
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf(" malformed jwt header: %v", err)
	}

	var parsedHeader map[string]interface{}
	if err := json.Unmarshal(header, &parsedHeader); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal jwt header: %v", err)
	}

	// pretty output
	parsedHeaderByte, err := json.MarshalIndent(parsedHeader, "", "    ")
	if err != nil {
		c.logger.Error("Could not marshal jwt header", "err", err)
		return "", nil, err
	}

	return string(parsedHeaderByte), parsedHeader, nil
}
