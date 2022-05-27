package v1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func padding(ciphertext []byte, blockSize int) []byte {
	pad := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(ciphertext, padtext...)
}

func unPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesCBCEncrypt(rawData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	rawData = padding(rawData, blockSize)
	cipherText := make([]byte, blockSize+len(rawData))
	iv := cipherText[:blockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], rawData)

	return cipherText, nil
}

func aesCBCDecrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	if len(encryptData)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptData, encryptData)
	encryptData = unPadding(encryptData)
	return encryptData, nil
}

// Encrypt encryption message. len(key) == 32
func Encrypt(message, key []byte) (string, error) {
	data, err := aesCBCEncrypt(message, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Decrypt decryption message. len(key) == 32
func Decrypt(message string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	dnData, err := aesCBCDecrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}
