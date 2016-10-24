package oaep

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/ssh-vault/crypto"
)

func TestOAEP(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	publicKey := &privateKey.PublicKey
	message := []byte("The quick brown fox jumps over the lazy dog")

	ciphertext, err := Encrypt(publicKey, message, []byte(""))
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(privateKey, ciphertext, []byte(""))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}

func TestOAEPLabel(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	publicKey := &privateKey.PublicKey
	message := []byte("The quick brown fox jumps over the lazy dog")

	label, err := crypto.GenerateNonce(64)
	if err != nil {
		t.Error(err)
	}

	ciphertext, err := Encrypt(publicKey, message, label)
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(privateKey, ciphertext, label)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}
