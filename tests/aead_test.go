package crypto_tests

import (
	"bytes"
	"testing"

	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

func TestAEAD(t *testing.T) {
	password, err := crypto.GenerateNonce(32)
	if err != nil {
		t.Error(err)
	}

	message := []byte("The quick brown fox jumps over the lazy dog")
	ciphertext, err := aead.Encrypt(password, message, []byte(""))
	if err != nil {
		t.Error(err)
	}

	plaintext, err := aead.Decrypt(password, ciphertext, []byte(""))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}
