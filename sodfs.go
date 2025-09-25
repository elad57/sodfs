package sodfs

//import file system
import (
	"os"
	"crypto/aes"
 	"encoding/hex"
)

type SODFS struct {
	EncryptionKey string
}


func encrypt(data []byte, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	block.Encrypt(encrypted, data)
	return []byte(hex.EncodeToString(encrypted)), nil
}

func decrypt(data []byte, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	decodedData := make([]byte, hex.DecodedLen(len(data)))
	_, err = hex.Decode(decodedData, data)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(decodedData))
	block.Decrypt(decrypted, decodedData)
	return decrypted, nil
}

// func decrypt(data []byte, key string) ([]byte, error) {
	
// }

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