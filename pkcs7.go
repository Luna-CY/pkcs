package pkcs

import (
	"bytes"
	"fmt"
)

// PKCS7Padding 实现了PKCS7填充
func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

// PKCS7Unpadding 实现了PKCS7填充的反向操作
func PKCS7Unpadding(plaintext []byte) ([]byte, error) {
	length := len(plaintext)
	if length == 0 {
		return nil, fmt.Errorf("plaintext is empty")
	}
	padding := int(plaintext[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return plaintext[:length-padding], nil
}
