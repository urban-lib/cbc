# CBC Encryption

```go
package main

import (
	"fmt"
	"github.com/urban-lib/cbc"
)

func main() {
	// must be  len(key) == 32
	key := []byte("qazxswedcvfrtgbnhy12312dasasdwd9")
	message := []byte(`hello world`)
	// Encryption
	encryptedMessage, err := cbc.Encrypt(message, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(encryptedMessage)
	// Decryption
	decryptedMessage, err := cbc.Decrypt(encryptedMessage, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(decryptedMessage)
}

```