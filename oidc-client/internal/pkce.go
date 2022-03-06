package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Constants defined in the RFC7636
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
const (
	charSet         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	charSetLength   = byte(len(charSet))
	minSize         = 43
	maxSize         = 128
	PKCEMethodPlain = "plain"
	PKCEMethodS256  = "S256"
)

// NewCodeVerifier generates a crypto secure
// random sequence of string from the allowed
// charset defined in RFC7636
func NewCodeVerifier(l int) (string, error) {
	if l < minSize || l > maxSize {
		return "", errors.New("length must be between 43 and 128")
	}

	randBytes, err := genCryptoSecureRandomBytes(l)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randBytes), nil

}

// NewCodeChallenge generated a New Code Challenge from the codeVerifier
//  * challenge = codeVerifier if method is "plain"
//  * as BASEURL-ENCODE(SHA256(codeVerifier)) otherwise
func NewCodeChallenge(codeVerifier string, method string) (string, error) {

	if method == PKCEMethodPlain {
		return codeVerifier, nil
	}

	h := sha256.New()
	_, err := h.Write([]byte(codeVerifier))
	if err != nil {
		return "", err
	}

	hashByte := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hashByte), nil
}

// genCryptoSecureRandomBytes generates an unbiased,
// crypto random sequence of bytes of length l
func genCryptoSecureRandomBytes(l int) ([]byte, error) {

	// the random sequence generated from the charSet
	randSequence := make([]byte, 0, l)

	// read length
	// NOTE: Arbitrary set to twice as long
	//       under the assumption that is more expensive to rand.Read()
	//       than to have some extra byte in memory
	randLength := l * 2

	// continue until the randSequence is full
	for {

		// Read a random byte buffer fo size randLength
		// https://pkg.go.dev/crypto/rand#example-Read
		b := make([]byte, randLength)
		_, err := rand.Read(b)
		if err != nil {
			return nil, err
		}

		// for each random byte
		for _, randByte := range b {

			// to avoid modulo bias towards certain character
			// only keep random byte that are valid index of the charset
			if randByte < charSetLength {

				// add the corresponding random index to sequence
				randSequence = append(randSequence, charSet[randByte])

				// return sequence when full
				if len(randSequence) == l {
					return randSequence, nil
				}

			}

		}

	}

}
