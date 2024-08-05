package pkcs

import (
	"bytes"
	"errors"
)

// PKCS5Padding 实现了PKCS5填充
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

// PKCS5UnPadding 实现了PKCS5填充的反向操作
func PKCS5UnPadding(origData []byte) ([]byte, error) {
	var length = len(origData)
	if 0 == length {
		return nil, errors.New("plaintext is empty")
	}

	var unPadding = int(origData[length-1])

	if unPadding > length {
		return nil, errors.New("invalid padding")
	}

	return origData[:(length - unPadding)], nil
}
