package pkcs

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

// PKCS1v15Padding 实现PKCS#1 v1.5的填充算法
func PKCS1v15Padding(data []byte, keySize int) ([]byte, error) {
	var paddingSize = keySize - len(data) - 3
	if paddingSize < 8 {
		return nil, fmt.Errorf("data too long for RSA key size")
	}

	var padtext = make([]byte, paddingSize)
	_, err := rand.Read(padtext)
	if err != nil {
		return nil, err
	}

	for i := 0; i < paddingSize; i++ {
		if padtext[i] == 0 {
			padtext[i] = 1
		}
	}

	padded := bytes.NewBuffer([]byte{0x00, 0x02})
	padded.Write(padtext)
	padded.WriteByte(0x00)
	padded.Write(data)

	return padded.Bytes(), nil
}

// PKCS1v15Unpadding 实现PKCS#1 v1.5的移除填充算法
func PKCS1v15Unpadding(data []byte) ([]byte, error) {
	if len(data) < 11 || data[0] != 0x00 || data[1] != 0x02 {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := 2; i < len(data); i++ {
		if data[i] == 0x00 {
			return data[i+1:], nil
		}
	}
	return nil, fmt.Errorf("invalid padding")
}
