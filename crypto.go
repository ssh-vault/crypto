package crypto

import "crypto/rand"

// GenerateNonce creates a new random nonce.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}
