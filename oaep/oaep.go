package oaep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Encrypt OAEP
func Encrypt(pub *PublicKey, msg, label []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(),
		rand.Reader,
		pub,
		msg,
		label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt OAEP
func Decrypt(priv *PrivateKey, ciphertext, label []byte) ([]byte, error) {
	plaintext, err := DecryptOAEP(sha256.New(),
		rand.Reader,
		priv,
		ciphertext,
		label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
