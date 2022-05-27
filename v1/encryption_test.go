package v1

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {

	secretKye := []byte("qwerty098765432qwdrftghy") // length == 32
	fmt.Println(len(secretKye))
	message := []byte(`hallo world`)
	encryptedData, err := Encrypt(message, secretKye)
	assert.NoError(t, err)
	fmt.Println(encryptedData)

	decryptedData, err := Decrypt(encryptedData, secretKye)
	assert.NoError(t, err)
	fmt.Println(decryptedData)
	assert.Equal(t, string(message), decryptedData)
}
