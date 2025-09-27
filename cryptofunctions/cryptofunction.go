package cryptofunctions

import (
	"crypto/aes"
	"errors"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func encrypt(data []byte, key string) ([]byte, error) {
	keyHash := sha256.Sum256([]byte(key))
	
	// Create AES cipher block
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Create nonce (number used once)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// Encrypt and authenticate the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	
	return ciphertext, nil
}

func decrypt(data []byte, key string) ([]byte, error) {
	// Create a SHA256 hash of the key to ensure it's 32 bytes (AES-256)
	keyHash := sha256.Sum256([]byte(key))
	
	// Create AES cipher block
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	
	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Check if data is long enough to contain nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	
	// Extract nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	
	// Decrypt and verify the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}