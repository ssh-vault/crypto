package aead

import (
	"bytes"
	"testing"

	"github.com/ssh-vault/crypto"
)

func TestAEAD(t *testing.T) {
	password, err := crypto.GenerateNonce(32)
	if err != nil {
		t.Error(err)
	}

	message := []byte("The quick brown fox jumps over the lazy dog")
	ciphertext, err := Encrypt(password, message, []byte(""))
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(password, ciphertext, []byte(""))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}
