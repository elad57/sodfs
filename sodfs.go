package sodfs

import (
	"os"
	"github.com/elad57/sodfs/cryptofunctions"
)

type SODFS struct {
	EncryptionKey string
}


func (sodfs *SODFS) WriteFile(filePath string, data []byte) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encryptedData, err := cryptofunctions.Encrypt(data, sodfs.EncryptionKey)
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
	decryptedData, err := cryptofunctions.Decrypt(data, sodfs.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}
