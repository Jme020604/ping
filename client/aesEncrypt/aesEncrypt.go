// this part of the program is for aes encrypting and decyrping messages
package aesEncrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// this function is for encrypting the messages
func EncryptAES(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	// Pad plaintext using PKCS7 padding
	plaintextBytes = PKCS7Padding(plaintextBytes)

	// Create a cipher block mode
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext[aes.BlockSize:], plaintextBytes)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	return hex.EncodeToString(ciphertext), nil
}

// this function is for decrypting the messages
func DecryptAES(key []byte, ct string) (string, error) {
	ciphertext, err := hex.DecodeString(ct)
	if err != nil {
		return "", errors.New("error decoding hex string: " + err.Error())
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext length is too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("error creating AES cipher: " + err.Error())
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(plaintext, ciphertext[16:]) // that [16:] is pure f***ing magic

	// Remove PKCS7 padding
	plaintext = PKCS7UnPadding(plaintext)

	return string(plaintext), nil
}

// this function adds pkcs7 padding
func PKCS7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// this function romves pkcs7 padding
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	if length == 0 {
		return nil
	}
	unpadding := int(plantText[length-1])
	if unpadding > length {
		return nil // or handle the invalid unpadding value accordingly
	}
	return plantText[:(length - unpadding)]
}
