package crypto

import "testing"

func TestGenerateNonce(t *testing.T) {
	nonces := make(map[string]int)
	for i := 0; i < 1000000; i++ {
		if nonce, err := GenerateNonce(32); err == nil {
			nonces[string(nonce)] = i
		} else {
			t.Error(err)
		}
	}
	if len(nonces) != 1000000 {
		t.Error("Nonces repeating")
	}
}
