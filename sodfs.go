package sodfs

//import file system
import (
	"crypto/aes"
	"errors"
	"os"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type SODFS struct {
	EncryptionKey string
}

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

func (sodfs *SODFS) WriteFile(filePath string, data []byte) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encryptedData, err := encrypt(data, sodfs.EncryptionKey)
	if err != nil {
		return err
	}

	_, err = file.Write(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

func (sodfs *SODFS) ReadFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	data := make([]byte, fileInfo.Size())
	_, err = file.Read(data)
	if err != nil {
		return nil, err
	}
	decryptedData, err := decrypt(data, sodfs.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}
