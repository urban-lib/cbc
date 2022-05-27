package cbc

import "encoding/base64"

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
